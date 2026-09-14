package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
)

const reconcileTimeout = 30 * time.Second

type CapabilitiesRegistry interface {
	GetDON(opts *bind.CallOpts, donId uint32) (capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo, error)
}

// the `configTracker` checks for updates on the assigned DON's membership in the on-chain `CapabilitiesRegistry` contract.
// If membership has changed, it updates the enclave's configuration with the newest membership.
type configTracker struct {
	capabilitiesRegistry   CapabilitiesRegistry
	logger                 logger.Logger
	donID                  uint32
	hostPort               string
	configPort             string
	refreshInterval        time.Duration
	initialT               uint32
	initialMasterPublicKey []byte
	requireBFTQuorum       bool
}

func NewConfigTracker(
	capabilitiesRegistry CapabilitiesRegistry,
	logger logger.Logger,
	donID uint32,
	hostPort, configPort string,
	refreshInterval time.Duration,
	initialT uint32,
	initialMasterPublicKey []byte,
	requireBFTQuorum bool,
) *configTracker {
	return &configTracker{
		capabilitiesRegistry:   capabilitiesRegistry,
		logger:                 logger,
		donID:                  donID,
		hostPort:               hostPort,
		configPort:             configPort,
		refreshInterval:        refreshInterval,
		initialT:               initialT,
		initialMasterPublicKey: initialMasterPublicKey,
		requireBFTQuorum:       requireBFTQuorum,
	}
}

func (ct *configTracker) Start(ctx context.Context) {
	ct.logger.Info("Starting periodic checks for DON configuration updates...")
	for {
		checkCtx, cancel := context.WithTimeout(ctx, reconcileTimeout)
		_, err := ct.checkUpdates(checkCtx, ct.logger, ct.capabilitiesRegistry, ct.donID, ct.hostPort, ct.configPort)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			ct.logger.Errorf("Error checking updates: %v", err)
		}

		timer := time.NewTimer(ct.refreshInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// checkUpdates compares the DON membership with the enclave config. It returns
// true when the enclave is configured, including when another writer wins the
// initial configuration race.
func (ct *configTracker) checkUpdates(ctx context.Context, lggr logger.Logger, reg CapabilitiesRegistry, donID uint32, hostPort, configPort string) (bool, error) {
	lggr.Infof("Fetching DON with ID: %d", donID)
	don, err := reg.GetDON(&bind.CallOpts{Context: ctx}, donID)
	if err != nil {
		return false, fmt.Errorf("failed to get DON: %w", err)
	}
	lggr.Infof("DON fetched successfully. NodeP2PIds count: %d", len(don.NodeP2PIds))
	for i, nodeId := range don.NodeP2PIds {
		lggr.Infof("DON Node %d: %x", i, nodeId)
	}

	if don.F == 0 {
		return false, fmt.Errorf("DON F value is 0, which indicates a misconfigured DON - skipping update")
	}

	lggr.Infof("Fetching enclave config from: %s", localhostPrefix+":"+hostPort+"/publicKeys")
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, localhostPrefix+":"+hostPort+"/publicKeys", nil)
	if err != nil {
		return false, fmt.Errorf("failed to create enclave config request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to fetch enclave config: %w", err)
	}
	defer util.SafeClose(resp)
	var out types.PublicKeyResponse
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %w", err)
		}
		if int64(len(body)) > types.MaxEnclaveResponseBodyBytes {
			return false, fmt.Errorf("enclave config response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return false, fmt.Errorf("failed to unmarshal enclave response (status %d, body: %s): %w", resp.StatusCode, string(body), err)
		}
	case http.StatusServiceUnavailable:
		// The enclave serves 503 on /publicKeys until it has a config. Leave the
		// current config empty so the comparison below sets the initial config.
		lggr.Info("Enclave has no config yet (503); proceeding to set the initial config")
	default:
		return false, fmt.Errorf("enclave config endpoint returned non-200 status: %d", resp.StatusCode)
	}
	lggr.Infof("Current enclave config - Signers count: %d, PublicKey: %s, T: %d, F: %d",
		len(out.Config.Signers), out.Config.MasterPublicKey, out.Config.T, out.Config.F)
	for i, signer := range out.Config.Signers {
		lggr.Infof("Current Signer %d: %x", i, signer)
	}

	lggr.Info("Comparing enclave config signers with DON node IDs...")
	donNodeIds := make([][]byte, len(don.NodeP2PIds))
	for i, nodeId := range don.NodeP2PIds {
		donNodeIds[i] = nodeId[:]
	}
	sort.Slice(donNodeIds, func(i, j int) bool {
		return bytes.Compare(donNodeIds[i], donNodeIds[j]) < 0
	})
	sort.Slice(out.Config.Signers, func(i, j int) bool {
		return bytes.Compare(out.Config.Signers[i], out.Config.Signers[j]) < 0
	})

	// Currently, we trigger an update on a change to the signers or f value of our DON.
	signersMatch := slices.EqualFunc(out.Config.Signers, donNodeIds, func(a, b []byte) bool {
		return bytes.Equal(a, b)
	})
	requiredF := uint32(don.F)
	fMatch := out.Config.F == requiredF

	// Validate the DON membership can reach the configured quorum. The host
	// enforces the threshold; here we surface a misconfiguration early. With
	// --require-bft-quorum the batch quorum is 2f+1, otherwise f+1.
	requiredSignatures := requiredF + 1
	if ct.requireBFTQuorum {
		requiredSignatures = 2*requiredF + 1
	}
	lggr.Infof("Quorum mode: requireBFTQuorum=%t, F=%d, requiredSignatures=%d, signers=%d",
		ct.requireBFTQuorum, requiredF, requiredSignatures, len(donNodeIds))
	if uint32(len(donNodeIds)) < requiredSignatures {
		lggr.Errorf("DON has %d signers but the configured quorum needs %d; requests will time out until membership grows",
			len(donNodeIds), requiredSignatures)
	}

	if !signersMatch || !fMatch {
		t := out.Config.T
		if t == 0 {
			t = ct.initialT
		}
		masterPublicKey := out.Config.MasterPublicKey
		if len(masterPublicKey) == 0 {
			masterPublicKey = ct.initialMasterPublicKey
		}
		config := types.EnclaveConfig{
			Signers:         donNodeIds,
			MasterPublicKey: masterPublicKey,
			T:               t,
			F:               requiredF,
		}
		alreadySet, err := postConfig(ctx, client, configPort, config)
		if err != nil {
			return false, fmt.Errorf("failed to update enclave config: %w", err)
		}
		if alreadySet {
			lggr.Info("Enclave config is already set; no update applied")
			return true, nil
		}
		lggr.Info("Successfully updated enclave config.")
	} else {
		lggr.Info("Signers match DON node IDs, no update needed.")
	}

	return true, nil
}

func postConfig(ctx context.Context, client *http.Client, configPort string, config types.EnclaveConfig) (bool, error) {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return false, fmt.Errorf("failed to marshal enclave config: %w", err)
	}
	payload, err := json.Marshal(types.ConfigRequest{Config: configBytes})
	if err != nil {
		return false, fmt.Errorf("failed to marshal config request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, localhostPrefix+":"+configPort+types.SetConfigPath, bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("failed to create config request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send config request: %w", err)
	}
	defer util.SafeClose(resp)
	if resp.StatusCode == http.StatusConflict {
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("config request failed with status %d", resp.StatusCode)
	}

	return false, nil
}
