package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	keypair, err := d.keychain.GetKeyPairForRequest(requestID)
	if err != nil {
		return nil, fmt.Errorf("getting keypair for request: %w", err)
	}

	cfg := d.getConfig()

	// See CallCapability for the rationale; mirror executor.go's normalization
	// so the relay-DON's strict params.Validate accepts what we send.
	owner = util.HexToAddress(owner).String()

	secrets := make([]confidentialrelay.SecretIdentifier, 0, len(req.GetRequests()))
	for _, secretRequest := range req.GetRequests() {
		// Default empty namespace to "main", mirroring what chainlink's
		// core/capabilities/confidentialrelay/handler.go does when handing
		// to vault (core/capabilities/vault/vaulttypes/types.go:
		// DefaultNamespace = "main"). The relay-DON's params.Validate
		// (chainlink-common pkg/capabilities/v2/actions/confidentialrelay/
		// types.go:228) rejects empty namespace, and the WASM SDK lets
		// users call rt.GetSecret without specifying one.
		namespace := secretRequest.GetNamespace()
		if namespace == "" {
			namespace = defaultSecretsNamespace
		}
		secrets = append(secrets, confidentialrelay.SecretIdentifier{
			Key:       secretRequest.GetId(),
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
		EnclavePublicKey: hex.EncodeToString(keypair.Public()),
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

	attestation, err := d.attest(confidentialrelay.DomainSecretsGet, params)
	if err != nil {
		return nil, fmt.Errorf("creating attestation: %w", err)
	}
	params.Attestation = attestation

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
			entries, skippedEntries := d.secretsEntries(bundle, params)
			combined, quorumErr := d.selectSecretsQuorumResult("GetSecrets", len(bundle.Responses), skippedEntries, entries, params, cfg)
			if quorumErr != nil {
				return confidentialrelay.SecretsResponseResult{}, fmt.Errorf("verifying secrets response: %w", quorumErr)
			}
			return combined, nil
		})
	if err != nil {
		return nil, err
	}

	// Prefer the DKG public key forwarded in the relay response (bound into the
	// signed result hash and verified above), falling back to the enclave's
	// configured key when absent. This keeps runtime secret reads correct across
	// reshares, where the configured key can be stale relative to the shares the
	// Vault DON just produced.
	masterPublicKey := cfg.MasterPublicKey
	if result.RawVaultPublicKey != "" {
		if vaultPublicKey, decodeErr := hex.DecodeString(result.RawVaultPublicKey); decodeErr != nil {
			d.logger.Warnw("[remoteDispatcher] failed to decode RawVaultPublicKey from relay response; using configured master public key", "err", decodeErr)
		} else {
			masterPublicKey = vaultPublicKey
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
	for _, orderedEntry := range ordered {
		if orderedEntry.entry == nil {
			responses = append(responses, &sdkpb.SecretResponse{
				Response: &sdkpb.SecretResponse_Error{
					Error: &sdkpb.SecretError{
						Id:        orderedEntry.id.Key,
						Namespace: orderedEntry.id.Namespace,
						Error:     "secret missing from relay response",
					},
				},
			})
			continue
		}
		entry := *orderedEntry.entry
		plaintext, err := d.decryptSecret(keypair, entry, masterPublicKey, int(cfg.T))
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
	requestedSecrets := uniqueSecretIDs(requested)
	isRequested := make(map[confidentialrelay.SecretIdentifier]bool, len(requestedSecrets))
	for _, id := range requestedSecrets {
		isRequested[id] = true
	}

	entryByID := make(map[confidentialrelay.SecretIdentifier]confidentialrelay.SecretEntry, len(got))
	for _, entry := range got {
		if !isRequested[entry.ID] {
			return nil, fmt.Errorf("unexpected secret %s/%s not in request", entry.ID.Namespace, entry.ID.Key)
		}
		if _, dup := entryByID[entry.ID]; dup {
			return nil, fmt.Errorf("duplicate secret %s/%s in response", entry.ID.Namespace, entry.ID.Key)
		}
		entryByID[entry.ID] = entry
	}

	ordered := make([]orderedSecret, 0, len(requestedSecrets))
	for _, id := range requestedSecrets {
		if entry, ok := entryByID[id]; ok {
			ordered = append(ordered, orderedSecret{id: id, entry: &entry})
		} else {
			ordered = append(ordered, orderedSecret{id: id})
		}
	}
	return ordered, nil
}

// decryptSecret NaCl-decrypts the TDH2 shares and aggregates them into the
// plaintext. Shares that fail to decode or decrypt are skipped so one faulty
// relay node cannot block decryption; the combiner verifies the rest.
func (d *remoteDispatcher) decryptSecret(keypair keychain.Keypair, entry confidentialrelay.SecretEntry, masterPublicKey []byte, threshold int) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	var shares [][]byte
	skipped := 0
	var lastErr error
	for i, encodedShare := range entry.EncryptedShares {
		encryptedShare, err := base64.StdEncoding.DecodeString(encodedShare)
		if err != nil {
			skipped++
			lastErr = fmt.Errorf("decoding share %d: %w", i, err)
			continue
		}
		share, err := keypair.Decrypt(encryptedShare)
		if err != nil {
			skipped++
			lastErr = fmt.Errorf("decrypting share %d: %w", i, err)
			continue
		}
		shares = append(shares, share)
	}
	if len(shares) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no decryptable shares (%d skipped): %w", skipped, lastErr)
		}
		return nil, errors.New("no encrypted shares provided")
	}
	d.logger.Debugw("[remoteDispatcher] decrypted secret shares",
		"encryptedShares", len(entry.EncryptedShares),
		"decryptedShares", len(shares),
		"skippedShares", skipped,
	)

	return d.combiner.AggregateShares(ciphertext, shares, masterPublicKey, threshold)
}

// secretsRelayEntry is one relay node's signed GetSecrets result, decoded but
// not yet signature-checked.
type secretsRelayEntry struct {
	bundleIndex int
	signedHash  [32]byte
	signature   confidentialrelay.RelayResponseSignature
	result      confidentialrelay.SecretsResponseResult
	description string
}

// secretsEntries decodes a secrets response bundle into entries for signature
// verification. Responses whose result cannot be hashed are returned as skipped
// diagnostics.
func (d *remoteDispatcher) secretsEntries(
	bundle confidentialrelay.SignedSecretsResponseBundle,
	params confidentialrelay.SecretsRequestParams,
) ([]secretsRelayEntry, []string) {
	entries := make([]secretsRelayEntry, 0, len(bundle.Responses))
	var skippedEntries []string
	for bundleIndex, response := range bundle.Responses {
		description := describeSecretsResult(response.Result)
		signedHash, err := response.Result.Hash(params)
		if err != nil {
			d.logger.Debugw("[remoteDispatcher] skipping relay response with unhashable result", "path", "GetSecrets", "idx", bundleIndex, "err", err)
			skippedEntries = append(skippedEntries, fmt.Sprintf("[idx=%d unhashable=%v %s]", bundleIndex, err, description))
			continue
		}
		entries = append(entries, secretsRelayEntry{
			bundleIndex: bundleIndex,
			signedHash:  signedHash,
			signature:   response.Signature,
			result:      response.Result,
			description: description,
		})
	}
	return entries, skippedEntries
}

// uniqueSecretIDs returns the requested identifiers without duplicates, in
// request order. The relay returns one entry per distinct identifier.
func uniqueSecretIDs(requested []confidentialrelay.SecretIdentifier) []confidentialrelay.SecretIdentifier {
	seen := make(map[confidentialrelay.SecretIdentifier]struct{}, len(requested))
	unique := make([]confidentialrelay.SecretIdentifier, 0, len(requested))
	for _, id := range requested {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

// selectSecretsQuorumResult verifies relay-DON signatures and, for each
// requested secret, selects the ciphertext and vault public key backed by at
// least F+1 distinct signers. It returns the union of the shares those signers
// sent. Shares can differ between signers, so each one is checked during
// decryption: TDH2 rejects invalid shares and the combiner dedupes by node index.
func (d *remoteDispatcher) selectSecretsQuorumResult(
	path string,
	rawBundleSize int,
	skippedEntries []string,
	entries []secretsRelayEntry,
	params confidentialrelay.SecretsRequestParams,
	cfg types.EnclaveConfig,
) (confidentialrelay.SecretsResponseResult, error) {
	if err := d.requireRelayVerifier(path, cfg); err != nil {
		return confidentialrelay.SecretsResponseResult{}, err
	}
	stats := secretsQuorumStats{
		path:          path,
		quorumSize:    int(cfg.F) + 1,
		rawBundleSize: rawBundleSize,
		hashable:      len(entries),
		unhashable:    len(skippedEntries),
	}

	votes := newSecretVotes(params.Secrets, d.maxEncryptedSharesPerRelayResult)
	entryDiagnostics := make([]string, 0, len(entries))
	for _, entry := range entries {
		signer, err := d.verifyRelaySigner(path, entry.bundleIndex, entry.signedHash, entry.signature, cfg)
		if err != nil {
			stats.invalidSignatures++
			entryDiagnostics = append(entryDiagnostics, fmt.Sprintf("[idx=%d signature=invalid(%v) claimedSigner=%s %s]",
				entry.bundleIndex, err, shortBytes(entry.signature.Signer), entry.description))
			continue
		}
		stats.validSignatures++

		if err := votes.validateNodeResponse(entry.result); err != nil {
			stats.malformed++
			d.logger.Debugw("[remoteDispatcher] skipping malformed relay secrets result", "path", path, "idx", entry.bundleIndex, "err", err)
			skippedEntries = append(skippedEntries, fmt.Sprintf("[idx=%d malformed=%v %s]", entry.bundleIndex, err, entry.description))
			continue
		}

		if dropped := votes.addVote(sha256.Sum256(signer), entry.result); dropped > 0 {
			d.logger.Warnw("[remoteDispatcher] truncating oversized relay share list",
				"path", path, "idx", entry.bundleIndex, "droppedShares", dropped, "max", d.maxEncryptedSharesPerRelayResult)
		}
		entryDiagnostics = append(entryDiagnostics, fmt.Sprintf("[idx=%d signature=valid signer=%s %s]",
			entry.bundleIndex, shortBytes(signer), entry.description))
	}

	combined, err := votes.selectWinners(stats.quorumSize)
	var noQuorum noSecretQuorumError
	if errors.As(err, &noQuorum) {
		return confidentialrelay.SecretsResponseResult{}, d.secretsQuorumError(noQuorum.secret, stats, entryDiagnostics, skippedEntries)
	}
	if err != nil {
		return confidentialrelay.SecretsResponseResult{}, err
	}

	combinedShareCount := 0
	for _, secret := range combined.Secrets {
		combinedShareCount += len(secret.EncryptedShares)
	}
	d.logger.Infow("[remoteDispatcher] relay-DON secrets quorum reached", append(stats.logFields(),
		"secrets", len(combined.Secrets),
		"mergedShares", combinedShareCount,
	)...)
	return combined, nil
}

// secretCandidateKey holds the fields of one secret's result that a quorum of
// signers must agree on. Shares may differ between signers.
type secretCandidateKey struct {
	ciphertext     string
	vaultPublicKey string
}

// tieBreakKey orders candidates with equal signer counts. The vault public key
// comes first so that tied secrets all resolve to the same key.
func (k secretCandidateKey) tieBreakKey() string {
	return k.vaultPublicKey + "\x00" + k.ciphertext
}

// secretCandidate is one candidate answer for a secret: the signers that voted
// for it and the encrypted shares they sent.
type secretCandidate struct {
	key                secretCandidateKey
	signers            map[[32]byte]struct{}
	shares             []string
	maxSharesPerSigner int
}

// addShares appends one signer's shares, capped at maxSharesPerSigner, and
// returns how many were dropped.
func (c *secretCandidate) addShares(signerShares []string) (dropped int) {
	if len(signerShares) > c.maxSharesPerSigner {
		dropped = len(signerShares) - c.maxSharesPerSigner
		signerShares = signerShares[:c.maxSharesPerSigner]
	}
	c.shares = append(c.shares, signerShares...)
	return dropped
}

// uniqueShares returns the candidate's shares with exact duplicates removed,
// in the order they were added.
func (c *secretCandidate) uniqueShares() []string {
	seen := make(map[string]struct{}, len(c.shares))
	unique := make([]string, 0, len(c.shares))
	for _, share := range c.shares {
		if _, dup := seen[share]; dup {
			continue
		}
		seen[share] = struct{}{}
		unique = append(unique, share)
	}
	return unique
}

// secretVotes collects verified relay nodes' votes for each requested secret.
type secretVotes struct {
	requestedSecrets   []confidentialrelay.SecretIdentifier
	secretIndexByID    map[confidentialrelay.SecretIdentifier]int
	candidatesBySecret []map[secretCandidateKey]*secretCandidate
	maxSharesPerSigner int
}

func newSecretVotes(requested []confidentialrelay.SecretIdentifier, maxSharesPerSigner int) *secretVotes {
	requestedSecrets := uniqueSecretIDs(requested)
	secretIndexByID := make(map[confidentialrelay.SecretIdentifier]int, len(requestedSecrets))
	candidatesBySecret := make([]map[secretCandidateKey]*secretCandidate, len(requestedSecrets))
	for secretIndex, id := range requestedSecrets {
		secretIndexByID[id] = secretIndex
		candidatesBySecret[secretIndex] = make(map[secretCandidateKey]*secretCandidate)
	}
	return &secretVotes{
		requestedSecrets:   requestedSecrets,
		secretIndexByID:    secretIndexByID,
		candidatesBySecret: candidatesBySecret,
		maxSharesPerSigner: maxSharesPerSigner,
	}
}

// validateNodeResponse checks that a relay node's result has exactly one entry
// per distinct requested secret. Results that fail do not count toward quorum.
func (v *secretVotes) validateNodeResponse(result confidentialrelay.SecretsResponseResult) error {
	if len(result.Secrets) != len(v.requestedSecrets) {
		return fmt.Errorf("expected %d secret responses, got %d", len(v.requestedSecrets), len(result.Secrets))
	}
	seen := make(map[confidentialrelay.SecretIdentifier]struct{}, len(result.Secrets))
	for _, secret := range result.Secrets {
		if _, requested := v.secretIndexByID[secret.ID]; !requested {
			return fmt.Errorf("unexpected secret %s/%s in response", secret.ID.Namespace, secret.ID.Key)
		}
		if _, dup := seen[secret.ID]; dup {
			return fmt.Errorf("duplicate secret %s/%s in response", secret.ID.Namespace, secret.ID.Key)
		}
		seen[secret.ID] = struct{}{}
	}
	return nil
}

// addVote records one signer's result, which must already have passed
// validateNodeResponse. A signer counts once per candidate. It returns how many
// shares were dropped by the per-signer cap.
func (v *secretVotes) addVote(signerKeyHash [32]byte, result confidentialrelay.SecretsResponseResult) (dropped int) {
	for _, secret := range result.Secrets {
		candidates := v.candidatesBySecret[v.secretIndexByID[secret.ID]]
		key := secretCandidateKey{ciphertext: secret.Ciphertext, vaultPublicKey: result.RawVaultPublicKey}
		candidate, ok := candidates[key]
		if !ok {
			candidate = &secretCandidate{
				key:                key,
				signers:            make(map[[32]byte]struct{}),
				maxSharesPerSigner: v.maxSharesPerSigner,
			}
			candidates[key] = candidate
		}
		if _, counted := candidate.signers[signerKeyHash]; counted {
			continue
		}
		candidate.signers[signerKeyHash] = struct{}{}
		dropped += candidate.addShares(secret.EncryptedShares)
	}
	return dropped
}

// noSecretQuorumError reports a requested secret with no candidate backed by
// a quorum of signers.
type noSecretQuorumError struct {
	secret confidentialrelay.SecretIdentifier
}

func (e noSecretQuorumError) Error() string {
	return fmt.Sprintf("no quorum for secret %s/%s", e.secret.Namespace, e.secret.Key)
}

// selectWinners picks, for each requested secret, the candidate with the most
// signers among those with at least quorumSize, breaking ties by
// tieBreakKey. Every winner must share one vault public key.
func (v *secretVotes) selectWinners(quorumSize int) (confidentialrelay.SecretsResponseResult, error) {
	combinedSecrets := make([]confidentialrelay.SecretEntry, 0, len(v.requestedSecrets))
	vaultPublicKey := ""
	for secretIndex, id := range v.requestedSecrets {
		var winner *secretCandidate
		for _, candidate := range v.candidatesBySecret[secretIndex] {
			signerCount := len(candidate.signers)
			if signerCount < quorumSize {
				continue
			}
			if winner == nil || signerCount > len(winner.signers) ||
				(signerCount == len(winner.signers) && candidate.key.tieBreakKey() < winner.key.tieBreakKey()) {
				winner = candidate
			}
		}
		if winner == nil {
			return confidentialrelay.SecretsResponseResult{}, noSecretQuorumError{secret: id}
		}

		if secretIndex == 0 {
			vaultPublicKey = winner.key.vaultPublicKey
		} else if winner.key.vaultPublicKey != vaultPublicKey {
			return confidentialrelay.SecretsResponseResult{}, fmt.Errorf(
				"relay-DON secrets results disagree on vault public key for %s/%s", id.Namespace, id.Key)
		}

		combinedSecrets = append(combinedSecrets, confidentialrelay.SecretEntry{
			ID:              id,
			Ciphertext:      winner.key.ciphertext,
			EncryptedShares: winner.uniqueShares(),
		})
	}
	return confidentialrelay.SecretsResponseResult{
		Secrets:           combinedSecrets,
		RawVaultPublicKey: vaultPublicKey,
	}, nil
}

// secretsQuorumStats holds the bundle counts logged by selectSecretsQuorumResult.
type secretsQuorumStats struct {
	path              string
	quorumSize        int
	rawBundleSize     int
	hashable          int
	unhashable        int
	malformed         int
	validSignatures   int
	invalidSignatures int
}

func (s secretsQuorumStats) logFields() []any {
	return []any{
		"path", s.path,
		"required", s.quorumSize,
		"rawBundleSize", s.rawBundleSize,
		"hashableEntries", s.hashable,
		"unhashable", s.unhashable,
		"malformed", s.malformed,
		"validSignatures", s.validSignatures,
		"invalidSignatures", s.invalidSignatures,
	}
}

func (d *remoteDispatcher) secretsQuorumError(secret confidentialrelay.SecretIdentifier, stats secretsQuorumStats, entryDiagnostics, skippedEntries []string) error {
	entryDetail := truncate(strings.Join(entryDiagnostics, " "), maxDiagLen)
	skippedDetail := truncate(strings.Join(skippedEntries, " "), maxDiagLen)
	d.logger.Errorw("[remoteDispatcher] relay-DON secrets quorum not reached", append(stats.logFields(),
		"secret", secret.Namespace+"/"+secret.Key,
		"entries", entryDetail,
		"skippedEntries", skippedDetail,
	)...)
	return fmt.Errorf("no relay-DON result reached quorum for %s/%s: need %d valid distinct signers (raw bundle %d, hashable %d, unhashable %d, malformed %d, %d valid signatures, %d invalid); entries: %s; skipped: %s",
		secret.Namespace, secret.Key,
		stats.quorumSize, stats.rawBundleSize, stats.hashable, stats.unhashable, stats.malformed, stats.validSignatures, stats.invalidSignatures,
		entryDetail, skippedDetail)
}
