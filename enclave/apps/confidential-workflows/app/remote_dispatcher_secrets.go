package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// defaultSecretsNamespace mirrors core/capabilities/vault/vaulttypes/types.go:
// DefaultNamespace in chainlink, which is what
// core/capabilities/confidentialrelay/handler.go uses when handing an empty
// namespace from a SecretsRequest to vault. We default at the sender so the
// relay-DON's params.Validate sees a non-empty namespace and the canonical
// hash binds to the same value on both sides.
const defaultSecretsNamespace = "main"

// relaySecretsCallbackIDDomain separates the relay callback ID derivation from
// other hashes. Its version changes whenever the derivation does.
const relaySecretsCallbackIDDomain = "chainlink-confidential-compute/relay-secrets-callback-id/v1\n"

// relaySecretsCallbackID derives the callback ID sent to the relay DON for a
// secrets request. The relay DON memoizes signed results, and the vault DON
// deduplicates requests, by (workflow, execution, callback ID), while the signed
// result is bound to the full request, including the enclave public key. A re-run
// of the execution on an enclave with a different key reuses the WASM callback ID
// and would be served a result it cannot verify or decrypt (INCIDENT-2692).
// Deriving the ID from the request gives each key and config its own identity at
// every layer, while an identical request keeps its ID, so retries still hit the
// relay memo. Attestation and the forwarded compute requests are authorization
// input that changes across retries on the same enclave, so they are excluded.
func relaySecretsCallbackID(params confidentialrelay.SecretsRequestParams) (int32, error) {
	params.Attestation = ""
	params.SignedComputeRequests = nil
	identity, err := json.Marshal(params)
	if err != nil {
		return 0, fmt.Errorf("marshalling secrets request identity: %w", err)
	}
	h := sha256.Sum256(append([]byte(relaySecretsCallbackIDDomain), identity...))
	// Setting the top bit is a formality: the negative ID cannot collide with the
	// non-negative IDs older enclaves send during rollout, and the nonzero ID is
	// always included in the response hash, which skips a zero callback ID.
	// ref: https://github.com/smartcontractkit/chainlink-common/blob/daa34bb8a9997e069365c6563c256ab2e32edb84/pkg/capabilities/v2/actions/confidentialrelay/types.go#L433-L435
	return int32(binary.BigEndian.Uint32(h[:4]) | 1<<31), nil
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
		CallbackID:       req.GetCallbackId(),
		Secrets:          secrets,
		EnclavePublicKey: hex.EncodeToString(kp.Public()),
		EnclaveConfig:    enclaveConfigFor(cfg),
		// Forwarded to the relay DON as the authorization for this secrets request.
		SignedComputeRequests: toRelaySignedComputeRequests(signedRequests),
	}

	relayCallbackID, err := relaySecretsCallbackID(params)
	if err != nil {
		return nil, err
	}
	// Relay and vault logs carry the derived ID; this maps it back to the WASM call.
	d.logger.Infow("[remoteDispatcher] derived relay callback ID for secrets request",
		"workflowID", workflowID,
		"executionID", executionID,
		"callbackID", req.GetCallbackId(),
		"relayCallbackID", relayCallbackID,
	)
	params.CallbackID = relayCallbackID

	att, err := d.attest(confidentialrelay.DomainSecretsGet, params)
	if err != nil {
		return nil, fmt.Errorf("creating attestation: %w", err)
	}
	params.Attestation = att

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshalling params: %w", err)
	}

	// Retry the gateway round-trip on a transient failure. See sendWithRetry.
	result, err := sendWithRetry(d, ctx, "secrets request", confidentialrelay.MethodSecretsGet, paramsJSON,
		func(resultJSON json.RawMessage) (confidentialrelay.SecretsResponseResult, error) {
			var bundle confidentialrelay.SignedSecretsResponseBundle
			if err := json.Unmarshal(resultJSON, &bundle); err != nil {
				return confidentialrelay.SecretsResponseResult{}, fmt.Errorf("unmarshalling secrets response bundle: %w", err)
			}
			d.logger.Debugw("[remoteDispatcher] received secrets response bundle", "rawBundleSize", len(bundle.Responses))
			entries, skipped := d.secretsEntries(bundle, params)
			idx, qErr := d.selectQuorumResult("GetSecrets", len(bundle.Responses), skipped, entries, cfg)
			if qErr != nil {
				return confidentialrelay.SecretsResponseResult{}, fmt.Errorf("verifying secrets response: %w", qErr)
			}
			return bundle.Responses[idx].Result, nil
		})
	if err != nil {
		return nil, err
	}

	// Prefer the DKG public key forwarded in the relay response (bound into the
	// signed result hash and verified above), falling back to the enclave's
	// configured key when absent. This keeps runtime secret reads correct across
	// reshares, where the configured key can be stale relative to the shares the
	// Vault DON just produced.
	masterPK := cfg.MasterPublicKey
	if result.RawVaultPublicKey != "" {
		if pk, derr := hex.DecodeString(result.RawVaultPublicKey); derr != nil {
			d.logger.Warnw("[remoteDispatcher] failed to decode RawVaultPublicKey from relay response; using configured master public key", "err", derr)
		} else {
			masterPK = pk
			d.logger.Debugw("[remoteDispatcher] using vault public key from relay response")
		}
	}

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

// secretsEntries decodes a secrets response bundle into quorum entries. A secrets
// result has no per-node ordering to normalize, so it groups on the hash the node
// signed.
func (d *remoteDispatcher) secretsEntries(
	bundle confidentialrelay.SignedSecretsResponseBundle,
	params confidentialrelay.SecretsRequestParams,
) ([]relayEntry, []string) {
	entries := make([]relayEntry, 0, len(bundle.Responses))
	var skipped []string
	for i, r := range bundle.Responses {
		desc := describeSecretsResult(r.Result)
		h, err := r.Result.Hash(params)
		if err != nil {
			d.logger.Debugw("[remoteDispatcher] skipping relay response with unhashable result", "path", "GetSecrets", "idx", i, "err", err)
			skipped = append(skipped, fmt.Sprintf("[idx=%d unhashable=%v %s]", i, err, desc))
			continue
		}
		entries = append(entries, relayEntry{
			sigHash:   h,
			groupHash: h,
			signature: r.Signature,
			desc:      desc,
			idx:       i,
		})
	}
	return entries, skipped
}
