package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/teeattestation"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"google.golang.org/protobuf/proto"
)

// defaultSecretsNamespace mirrors core/capabilities/vault/vaulttypes/types.go:
// DefaultNamespace in chainlink, which is what
// core/capabilities/confidentialrelay/handler.go uses when handing an empty
// namespace from a SecretsRequest to vault. We default at the sender so the
// relay-DON's params.Validate sees a non-empty namespace and the canonical
// hash binds to the same value on both sides.
const defaultSecretsNamespace = "main"

// RemoteDispatcher dispatches requests to a relay DON via the Gateway.
// This enables WASM binaries to invoke remote capabilities and fetch secrets
// at runtime. A single instance is shared across all workflow executions;
// workflowID and requestID are passed per-call.
type RemoteDispatcher interface {
	CallCapability(ctx context.Context, workflowID string, owner string, executionID string, orgID string, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error)
	GetSecrets(ctx context.Context, workflowID string, requestID [32]byte, req *sdkpb.GetSecretsRequest, owner string, executionID string, orgID string, signedRequests []types.SignedComputeRequest) ([]*sdkpb.SecretResponse, error)
	// SetConfig updates the dispatcher's enclave config (MasterPublicKey,
	// threshold, etc.) after the enclave receives its on-chain config.
	SetConfig(config types.EnclaveConfig)
}

// --- Implementation ---

type remoteDispatcher struct {
	client   *gateway.GatewayClient
	attestor attestor.Attestor
	configMu sync.RWMutex
	config   types.EnclaveConfig
	logger   logger.Logger
	keychain keychain.Keychain
	combiner combiner.Combiner
	verifier signatureverifier.SignatureVerifier
}

var _ RemoteDispatcher = (*remoteDispatcher)(nil)

func (d *remoteDispatcher) SetConfig(config types.EnclaveConfig) {
	d.configMu.Lock()
	defer d.configMu.Unlock()
	d.config = config
}

// getConfig returns a coherent snapshot of the enclave config. Callers take one
// snapshot per request so a concurrent SetConfig cannot tear reads mid-execution.
func (d *remoteDispatcher) getConfig() types.EnclaveConfig {
	d.configMu.RLock()
	defer d.configMu.RUnlock()
	return d.config
}

// NewRemoteDispatcher creates a RemoteDispatcher backed by a GatewayClient.
// The attestor creates Nitro attestation documents for relay DON validation.
// keychain and combiner are required for remote secret fetching (TDH2 decryption).
// verifier is used on the gateway->enclave hop to verify F+1 relay-DON
// signatures over the response before the enclave consumes it.
func NewRemoteDispatcher(
	client *gateway.GatewayClient,
	att attestor.Attestor,
	config types.EnclaveConfig,
	lggr logger.Logger,
	kc keychain.Keychain,
	comb combiner.Combiner,
	verifier signatureverifier.SignatureVerifier,
) RemoteDispatcher {
	return &remoteDispatcher{
		client:   client,
		attestor: att,
		config:   config,
		logger:   lggr,
		keychain: kc,
		combiner: comb,
		verifier: verifier,
	}
}

func (d *remoteDispatcher) CallCapability(ctx context.Context, workflowID string, owner string, executionID string, orgID string, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	payloadBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshalling capability request: %w", err)
	}

	// Mirror capabilities/framework/executor.go: chainlink hands workflowOwner
	// to CC as a 40-char hex string without 0x prefix (see
	// chainlink core/services/workflows/v2/config.go:WorkflowOwner). The
	// relay-DON's params.Validate (chainlink-common
	// pkg/capabilities/v2/actions/confidentialrelay/types.go:validateOwnerAddress)
	// requires the canonical 0x-prefixed 20-byte hex form, so normalize here
	// before the params are hashed and shipped over the gateway.
	owner = util.HexToAddress(owner).String()

	cfg := d.getConfig()
	params := confidentialrelay.CapabilityRequestParams{
		WorkflowID:    workflowID,
		Owner:         owner,
		ExecutionID:   executionID,
		OrgID:         orgID,
		ReferenceID:   strconv.Itoa(int(req.GetCallbackId())),
		CapabilityID:  req.GetId(),
		Payload:       base64.StdEncoding.EncodeToString(payloadBytes),
		EnclaveConfig: enclaveConfigFor(cfg),
	}

	att, err := d.attest(confidentialrelay.DomainCapabilityExec, params)
	if err != nil {
		return nil, fmt.Errorf("creating attestation: %w", err)
	}
	params.Attestation = att

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshalling params: %w", err)
	}

	resultJSON, err := d.client.SendRequest(ctx, confidentialrelay.MethodCapabilityExec, paramsJSON)
	if err != nil {
		return nil, fmt.Errorf("sending capability request: %w", err)
	}

	var bundle confidentialrelay.SignedCapabilityResponseBundle
	if err := json.Unmarshal(resultJSON, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshalling capability response bundle: %w", err)
	}

	d.logger.Debugw("[remoteDispatcher] received capability response bundle", "rawBundleSize", len(bundle.Responses))
	entries := make([]relayEntry, 0, len(bundle.Responses))
	unhashable := 0
	for i, r := range bundle.Responses {
		h, hErr := r.Result.Hash(params)
		if hErr != nil {
			unhashable++
			d.logger.Debugw("[remoteDispatcher] skipping relay response with unhashable result", "path", "CallCapability", "idx", i, "err", hErr)
			continue
		}
		entries = append(entries, relayEntry{hash: h, signature: r.Signature, idx: i})
	}
	idx, err := d.selectQuorumResult("CallCapability", len(bundle.Responses), unhashable, entries, cfg)
	if err != nil {
		return nil, fmt.Errorf("verifying capability response: %w", err)
	}
	result := bundle.Responses[idx].Result

	if result.Error != "" {
		return &sdkpb.CapabilityResponse{
			Response: &sdkpb.CapabilityResponse_Error{
				Error: result.Error,
			},
		}, nil
	}

	respBytes, err := base64.StdEncoding.DecodeString(result.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding capability response payload: %w", err)
	}

	var capResp sdkpb.CapabilityResponse
	if err := proto.Unmarshal(respBytes, &capResp); err != nil {
		return nil, fmt.Errorf("unmarshalling capability response proto: %w", err)
	}

	return &capResp, nil
}

// toRelaySignedComputeRequests copies the signed compute requests into the chainlink-common
// type so the relay reconstructs the same ComputeRequest.Hash the nodes signed.
func toRelaySignedComputeRequests(reqs []types.SignedComputeRequest) []confidentialrelay.SignedComputeRequest {
	if len(reqs) == 0 {
		return nil
	}
	out := make([]confidentialrelay.SignedComputeRequest, len(reqs))
	for i, r := range reqs {
		out[i] = confidentialrelay.SignedComputeRequest{
			ComputeRequest: confidentialrelay.ComputeRequest{
				RequestID:                    r.RequestID,
				ApplicationRequestID:         r.ApplicationRequestID,
				PublicData:                   r.PublicData,
				Ciphertexts:                  r.Ciphertexts,
				CiphertextNames:              r.CiphertextNames,
				EncryptedDecryptionKeyShares: r.EncryptedDecryptionKeyShares,
				EnclaveEphemeralPublicKey:    r.EnclaveEphemeralPublicKey,
				MasterPublicKey:              r.MasterPublicKey,
				AppID:                        r.AppID,
				Version:                      r.Version,
			},
			Signature: r.Signature,
		}
	}
	return out
}

func (d *remoteDispatcher) GetSecrets(ctx context.Context, workflowID string, requestID [32]byte, req *sdkpb.GetSecretsRequest, owner string, executionID string, orgID string, signedRequests []types.SignedComputeRequest) ([]*sdkpb.SecretResponse, error) {
	kp, err := d.keychain.GetKeyPairForRequest(requestID)
	if err != nil {
		return nil, fmt.Errorf("getting keypair for request: %w", err)
	}

	cfg := d.getConfig()

	// See CallCapability for the rationale; mirror executor.go's normalization
	// so the relay-DON's strict params.Validate accepts what we send.
	owner = util.HexToAddress(owner).String()

	secrets := make([]confidentialrelay.SecretIdentifier, 0, len(req.GetRequests()))
	for _, sr := range req.GetRequests() {
		// Default empty namespace to "main", mirroring what chainlink's
		// core/capabilities/confidentialrelay/handler.go does when handing
		// to vault (core/capabilities/vault/vaulttypes/types.go:
		// DefaultNamespace = "main"). The relay-DON's params.Validate
		// (chainlink-common pkg/capabilities/v2/actions/confidentialrelay/
		// types.go:228) rejects empty namespace, and the WASM SDK lets
		// users call rt.GetSecret without specifying one.
		namespace := sr.GetNamespace()
		if namespace == "" {
			namespace = defaultSecretsNamespace
		}
		secrets = append(secrets, confidentialrelay.SecretIdentifier{
			Key:       sr.GetId(),
			Namespace: namespace,
		})
	}

	params := confidentialrelay.SecretsRequestParams{
		WorkflowID:       workflowID,
		Owner:            owner,
		ExecutionID:      executionID,
		OrgID:            orgID,
		Secrets:          secrets,
		EnclavePublicKey: hex.EncodeToString(kp.Public()),
		EnclaveConfig:    enclaveConfigFor(cfg),
		// Forwarded to the relay DON as the authorization for this secrets request.
		SignedComputeRequests: toRelaySignedComputeRequests(signedRequests),
	}

	att, err := d.attest(confidentialrelay.DomainSecretsGet, params)
	if err != nil {
		return nil, fmt.Errorf("creating attestation: %w", err)
	}
	params.Attestation = att

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshalling params: %w", err)
	}

	resultJSON, err := d.client.SendRequest(ctx, confidentialrelay.MethodSecretsGet, paramsJSON)
	if err != nil {
		return nil, fmt.Errorf("sending secrets request: %w", err)
	}

	var bundle confidentialrelay.SignedSecretsResponseBundle
	if err := json.Unmarshal(resultJSON, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshalling secrets response bundle: %w", err)
	}

	d.logger.Debugw("[remoteDispatcher] received secrets response bundle", "rawBundleSize", len(bundle.Responses))
	entries := make([]relayEntry, 0, len(bundle.Responses))
	unhashable := 0
	for i, r := range bundle.Responses {
		h, hErr := r.Result.Hash(params)
		if hErr != nil {
			unhashable++
			d.logger.Debugw("[remoteDispatcher] skipping relay response with unhashable result", "path", "GetSecrets", "idx", i, "err", hErr)
			continue
		}
		entries = append(entries, relayEntry{hash: h, signature: r.Signature, idx: i})
	}
	idx, err := d.selectQuorumResult("GetSecrets", len(bundle.Responses), unhashable, entries, cfg)
	if err != nil {
		return nil, fmt.Errorf("verifying secrets response: %w", err)
	}
	result := bundle.Responses[idx].Result

	// Use the enclave's own master public key from config, not the relay response.
	// The enclave already knows this from the on-chain DON config (populated after DKG).
	masterPK := cfg.MasterPublicKey

	// Validate the relay's secrets against the request and rebuild the slice
	// in request order: reject unexpected or duplicated IDs, and emit one
	// response per requested secret in order. Downstream WASM consumers index
	// secrets positionally, so a reordered, padded, or trimmed response could
	// otherwise deliver the wrong secret to the wrong consumer. [CL112-16]
	ordered, err := orderRelaySecrets(secrets, result.Secrets)
	if err != nil {
		return nil, fmt.Errorf("validating secrets response: %w", err)
	}

	responses := make([]*sdkpb.SecretResponse, 0, len(ordered))
	for _, os := range ordered {
		if os.entry == nil {
			responses = append(responses, &sdkpb.SecretResponse{
				Response: &sdkpb.SecretResponse_Error{
					Error: &sdkpb.SecretError{
						Id:        os.id.Key,
						Namespace: os.id.Namespace,
						Error:     "secret missing from relay response",
					},
				},
			})
			continue
		}
		entry := *os.entry
		plaintext, err := d.decryptSecret(kp, entry, masterPK, int(cfg.T))
		if err != nil {
			responses = append(responses, &sdkpb.SecretResponse{
				Response: &sdkpb.SecretResponse_Error{
					Error: &sdkpb.SecretError{
						Id:        entry.ID.Key,
						Namespace: entry.ID.Namespace,
						Error:     err.Error(),
					},
				},
			})
			continue
		}
		responses = append(responses, &sdkpb.SecretResponse{
			Response: &sdkpb.SecretResponse_Secret{
				Secret: &sdkpb.Secret{
					Id:        entry.ID.Key,
					Namespace: entry.ID.Namespace,
					Value:     string(plaintext),
				},
			},
		})
	}
	return responses, nil
}

type orderedSecret struct {
	id    confidentialrelay.SecretIdentifier
	entry *confidentialrelay.SecretEntry // nil when the relay omitted this secret
}

// orderRelaySecrets validates the relay's secret entries against the requested
// identifiers and returns them in request order. It rejects entries whose ID
// was not requested and duplicate IDs; a requested secret the relay omitted is
// returned with a nil entry so the caller can surface a per-secret error while
// keeping positional alignment. [CL112-16]
func orderRelaySecrets(requested []confidentialrelay.SecretIdentifier, got []confidentialrelay.SecretEntry) ([]orderedSecret, error) {
	type idKey struct{ namespace, key string }
	want := make(map[idKey]bool, len(requested))
	order := make([]confidentialrelay.SecretIdentifier, 0, len(requested))
	for _, s := range requested {
		k := idKey{s.Namespace, s.Key}
		if !want[k] {
			want[k] = true
			order = append(order, s)
		}
	}

	byID := make(map[idKey]confidentialrelay.SecretEntry, len(got))
	for i := range got {
		k := idKey{got[i].ID.Namespace, got[i].ID.Key}
		if !want[k] {
			return nil, fmt.Errorf("unexpected secret %s/%s not in request", got[i].ID.Namespace, got[i].ID.Key)
		}
		if _, dup := byID[k]; dup {
			return nil, fmt.Errorf("duplicate secret %s/%s in response", got[i].ID.Namespace, got[i].ID.Key)
		}
		byID[k] = got[i]
	}

	ordered := make([]orderedSecret, 0, len(order))
	for _, id := range order {
		k := idKey{id.Namespace, id.Key}
		if e, ok := byID[k]; ok {
			e := e
			ordered = append(ordered, orderedSecret{id: id, entry: &e})
		} else {
			ordered = append(ordered, orderedSecret{id: id})
		}
	}
	return ordered, nil
}

// decryptSecret NaCl-decrypts the TDH2 shares, then aggregates them to recover plaintext.
func (d *remoteDispatcher) decryptSecret(kp keychain.Keypair, entry confidentialrelay.SecretEntry, masterPK []byte, threshold int) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	var shares [][]byte
	for i, encShare := range entry.EncryptedShares {
		encBytes, err := base64.StdEncoding.DecodeString(encShare)
		if err != nil {
			return nil, fmt.Errorf("decoding share %d: %w", i, err)
		}
		share, err := kp.Decrypt(encBytes)
		if err != nil {
			return nil, fmt.Errorf("decrypting share %d: %w", i, err)
		}
		shares = append(shares, share)
	}

	return d.combiner.AggregateShares(ciphertext, shares, masterPK, threshold)
}

// relayEntry is one decoded per-node response from the gateway bundle: the
// canonical hash of its logical result, the node's single signature, and its
// index in the original bundle so the caller can recover the chosen result.
type relayEntry struct {
	hash      [32]byte
	signature confidentialrelay.RelayResponseSignature
	idx       int
}

// selectQuorumResult is the trust anchor on the gateway->enclave hop. The gateway
// is a dumb fan-in: it forwards every per-node response it collected, unverified,
// and may include invalid or foreign signatures injected by a compromised relay
// node. The enclave is what decides. We verify each response's signature against
// the relay-DON signer set, group the valid signers by response hash, and return
// the index of a response whose hash is backed by F+1 valid distinct signers.
//
// Verification is tolerant: invalid or foreign signatures are skipped, not fatal,
// so noise a faulty node stuffs into the bundle cannot deny service. A faulty node
// can equivocate (validly sign two different results), but honest nodes sign only
// the true result, so a forged result reaches at most F valid signers (< F+1) and
// can never win; the true result reaches F+1 from the honest majority. The winner
// is therefore unique; the deterministic tie-break is purely defensive.
//
// We verify against EnclaveConfig.Signers / EnclaveConfig.F — the same signer set
// used to verify workflow-DON->enclave requests. The deployment invariant is that
// the workflow DON and the relay DON are the same DON wearing two hats. If that
// ever changes, this is the spot to introduce a separate RelayDON signer set.
func (d *remoteDispatcher) selectQuorumResult(path string, rawBundleSize, unhashable int, entries []relayEntry, cfg types.EnclaveConfig) (int, error) {
	if d.verifier == nil {
		d.logger.Errorw("[remoteDispatcher] relay-DON signature verification failed", "path", path, "reason", "verifier not configured")
		return 0, fmt.Errorf("relay signature verifier not configured")
	}
	if len(cfg.Signers) == 0 {
		d.logger.Errorw("[remoteDispatcher] relay-DON signature verification failed", "path", path, "reason", "signer set not configured")
		return 0, fmt.Errorf("DON signer set not configured")
	}
	required := int(cfg.F) + 1

	// hash -> set of valid distinct signer fingerprints, plus the first bundle
	// index that contributed a valid signature for that hash.
	signersByHash := make(map[[32]byte]map[[32]byte]struct{})
	firstIdxByHash := make(map[[32]byte]int)
	validSignatures := 0
	invalidSignatures := 0
	for _, e := range entries {
		prefixed := confidentialrelay.RelayResponseSignaturePayload(e.hash)
		signer, err := d.verifier.VerifySignature(prefixed, e.signature.Signature, cfg.Signers)
		if err != nil {
			// Untrusted gateway / faulty node noise. Skip, do not fail.
			invalidSignatures++
			d.logger.Debugw("[remoteDispatcher] skipping invalid or foreign relay signature", "path", path, "idx", e.idx, "err", err)
			continue
		}
		validSignatures++
		set, ok := signersByHash[e.hash]
		if !ok {
			set = make(map[[32]byte]struct{})
			signersByHash[e.hash] = set
			firstIdxByHash[e.hash] = e.idx
		}
		set[sha256.Sum256(signer)] = struct{}{}
	}

	// Collect the hashes that reached quorum and pick deterministically: most
	// valid signers first, then lexicographically smallest hash.
	type qualified struct {
		hash  [32]byte
		count int
	}
	var winners []qualified
	maxValidForAnyResult := 0
	for h, set := range signersByHash {
		if len(set) > maxValidForAnyResult {
			maxValidForAnyResult = len(set)
		}
		if len(set) >= required {
			winners = append(winners, qualified{hash: h, count: len(set)})
		}
	}
	if len(winners) == 0 {
		d.logger.Errorw("[remoteDispatcher] relay-DON quorum not reached",
			"path", path,
			"required", required,
			"rawBundleSize", rawBundleSize,
			"hashableEntries", len(entries),
			"unhashable", unhashable,
			"validSignatures", validSignatures,
			"invalidSignatures", invalidSignatures,
			"distinctResults", len(signersByHash),
			"maxValidForAnyResult", maxValidForAnyResult,
		)
		return 0, fmt.Errorf("no relay-DON result reached quorum: need %d valid distinct signers (raw bundle %d, hashable %d, %d valid signatures, %d invalid, max %d for any single result)", required, rawBundleSize, len(entries), validSignatures, invalidSignatures, maxValidForAnyResult)
	}
	sort.Slice(winners, func(i, j int) bool {
		if winners[i].count != winners[j].count {
			return winners[i].count > winners[j].count
		}
		return bytes.Compare(winners[i].hash[:], winners[j].hash[:]) < 0
	})
	d.logger.Infow("[remoteDispatcher] relay-DON quorum reached",
		"path", path,
		"required", required,
		"validSigners", winners[0].count,
		"rawBundleSize", rawBundleSize,
		"hashableEntries", len(entries),
		"unhashable", unhashable,
		"validSignatures", validSignatures,
		"invalidSignatures", invalidSignatures,
		"distinctResults", len(signersByHash),
		"maxValidForAnyResult", maxValidForAnyResult,
	)
	return firstIdxByHash[winners[0].hash], nil
}

// attest creates a Nitro attestation of the params content.
// The UserData is SHA-256(DomainSeparator + "\n" + domainTag + "\n" + paramsJSON).
func (d *remoteDispatcher) attest(domainTag string, content any) (string, error) {
	if d.attestor == nil {
		return "", nil
	}
	data, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("marshalling attestation content: %w", err)
	}
	doc, err := d.attestor.CreateAttestation(teeattestation.DomainHash(domainTag, data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(doc), nil
}

// enclaveConfigFor maps the enclave's local types.EnclaveConfig to the
// parallel confidentialrelay.EnclaveConfig struct that travels in every
// outgoing relay request. The relay-DON handler verifies the returned
// fields against onchain DON state before treating the attested request as
// trusted (Sigma Prime CL112-01 / PRIV-458).
func enclaveConfigFor(c types.EnclaveConfig) *confidentialrelay.EnclaveConfig {
	signers := make([][]byte, len(c.Signers))
	for i, s := range c.Signers {
		dup := make([]byte, len(s))
		copy(dup, s)
		signers[i] = dup
	}
	mpk := append([]byte(nil), c.MasterPublicKey...)
	return &confidentialrelay.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: mpk,
		T:               c.T,
		F:               c.F,
	}
}
