package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

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
}

func NewConfigTracker(
	capabilitiesRegistry CapabilitiesRegistry,
	logger logger.Logger,
	donID uint32,
	hostPort, configPort string,
	refreshInterval time.Duration,
	initialT uint32,
	initialMasterPublicKey []byte,
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
	}
}

func (ct *configTracker) Start() {
	ct.logger.Info("Starting periodic checks for DON configuration updates...")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	configSet, err := ct.checkUpdates(ct.logger, ct.capabilitiesRegistry, ct.donID, ct.hostPort, ct.configPort)
	if err != nil {
		ct.logger.Errorf("Error checking updates: %v", err)
	}
	if configSet {
		ct.waitForShutdown(sigChan)
		return
	}

	ticker := time.NewTicker(ct.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			configSet, err = ct.checkUpdates(ct.logger, ct.capabilitiesRegistry, ct.donID, ct.hostPort, ct.configPort)
			if err != nil {
				ct.logger.Errorf("Error checking updates: %v", err)
			}
			if configSet {
				ticker.Stop()
				ct.waitForShutdown(sigChan)
				return
			}
		case <-sigChan:
			ct.logger.Info("Received kill signal, stopping periodic checks")
			return
		}
	}
}

// waitForShutdown blocks until a kill signal is received. It is used after the
// config has been set, so the tracker sits idle instead of polling for updates.
func (ct *configTracker) waitForShutdown(sigChan <-chan os.Signal) {
	ct.logger.Info("Config set, stopping periodic checks and sitting idle")
	<-sigChan
	ct.logger.Info("Received kill signal, stopping")
}

// checkUpdates fetches the DON membership and, if it differs from the enclave's
// current config, updates the config. It returns true once the config has been
// confirmed set: either after a successful update or when it already matches.
func (ct *configTracker) checkUpdates(lggr logger.Logger, reg CapabilitiesRegistry, donID uint32, hostPort, configPort string) (bool, error) {
	lggr.Infof("Fetching DON with ID: %d", donID)
	don, err := reg.GetDON(nil, donID)
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
	resp, err := client.Get(localhostPrefix + ":" + hostPort + "/publicKeys")
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
		configBytes, err := json.Marshal(config)
		if err != nil {
			return false, fmt.Errorf("failed to marshal enclave config: %w", err)
		}
		_, err = util.SetNodeConfig(context.Background(), types.Enclave{EnclaveURL: localhostPrefix + ":" + configPort}, types.ConfigRequest{Config: configBytes}, nil)
		if err != nil {
			return false, fmt.Errorf("failed to update enclave config: %w", err)
		}
		lggr.Info("Successfully updated enclave config.")
	} else {
		lggr.Info("Signers match DON node IDs, no update needed.")
	}

	return true, nil
}
