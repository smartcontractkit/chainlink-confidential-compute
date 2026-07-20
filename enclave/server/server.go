package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/metrics"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/smartcontractkit/confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

// `enclaveServer` is a cloud provider-agnostic server that handles incoming requests to the enclave.
// It uses an injected attestor, keychain, signature verifier, combiner, and enclave application to process requests.
// It can export data to its logger and emitter.
type enclaveServer struct {
	app            types.EnclaveApp
	attestor       attestor.Attestor
	logger         *log.Logger
	keychain       keychain.Keychain
	verifier       signatureverifier.SignatureVerifier
	combiner       combiner.Combiner
	config         types.EnclaveConfig
	emitter        types.Emitter
	configLock     sync.Mutex
	configSet      bool
	allowReconfig  bool
	inProgressReqs *util.Cache[struct{}]
	executedReqs   *util.Cache[struct{}]
	reqsLock       sync.RWMutex
	// pendingConfigVotes accumulates signed config-update votes keyed by the
	// proposed config hash. The value is the set of signer-public-key hashes that
	// have voted for that config. Guarded by configLock.
	pendingConfigVotes *util.Cache[map[[32]byte]struct{}]
	// pubKeyAttestations caches attested /publicKeys responses keyed by the
	// attestation-content hash (PublicKeyHash).
	pubKeyAttestations *util.Cache[[]byte]
	// attestationGroup collapses concurrent pubKeyAttestations misses for the
	// same content into a single NSM attestation.
	attestationGroup singleflight.Group
	// execSem bounds concurrent /requests executions. The enclave runs on a fixed
	// memory carve-out and instantiates a fresh WASM runtime per execution, so
	// unbounded concurrency can exhaust memory and wedge the enclave. Excess
	// requests are rejected fast with 429 rather than run (backpressure).
	execSem                 *semaphore.Weighted
	maxConcurrentExecutions int64
}

type RequestTemplate struct {
	URL         string   `json:"url"`
	Headers     []string `json:"headers"`
	Body        string   `json:"body"`
	Method      string   `json:"method"`
	ContentType string   `json:"contentType"`
}

// DefaultMaxConcurrentExecutions bounds concurrent /requests executions when the
// caller does not override it. Deliberately conservative for the heaviest app
// (confidential-workflows instantiates a fresh WASM runtime per execution against
// a fixed enclave memory budget), so this protects against OOM/wedge. Lighter
// apps (e.g. confidential-http) should raise it via WithMaxConcurrentExecutions.
// Raise it only against a measured per-execution footprint (see GET /memory);
// prefer scaling out + a host-side queue over a very large value.
const DefaultMaxConcurrentExecutions int64 = 6

// ServerOption configures an enclaveServer.
type ServerOption func(*enclaveServer)

// WithMaxConcurrentExecutions overrides the concurrent-execution limit.
func WithMaxConcurrentExecutions(n int64) ServerOption {
	return func(s *enclaveServer) {
		if n > 0 {
			s.maxConcurrentExecutions = n
		}
	}
}

func NewEnclaveServer(
	app types.EnclaveApp,
	attestor attestor.Attestor,
	logger *log.Logger,
	keychain keychain.Keychain,
	verifier signatureverifier.SignatureVerifier,
	combiner combiner.Combiner,
	emitter types.Emitter,
	config types.EnclaveConfig,
	allowReconfig bool,
	opts ...ServerOption,
) *enclaveServer {
	replayCacheTTL := types.DefaultKeypairExpiration
	inProgressReqs := util.NewBoundedCache[struct{}](&replayCacheTTL, nil, types.MaxReplayCacheEntries)
	executedReqs := util.NewBoundedCache[struct{}](&replayCacheTTL, nil, types.MaxReplayCacheEntries)
	configVoteTTL := types.ConfigVoteTTL
	pendingConfigVotes := util.NewCache[map[[32]byte]struct{}](&configVoteTTL, nil)
	pubKeyAttestationTTL := types.PublicKeyAttestationCacheTTL
	pubKeyAttestations := util.NewCache[[]byte](&pubKeyAttestationTTL, nil)

	s := &enclaveServer{
		app:                     app,
		attestor:                attestor,
		logger:                  logger,
		keychain:                keychain,
		verifier:                verifier,
		combiner:                combiner,
		emitter:                 emitter,
		config:                  config,
		allowReconfig:           allowReconfig,
		inProgressReqs:          inProgressReqs,
		executedReqs:            executedReqs,
		pendingConfigVotes:      pendingConfigVotes,
		pubKeyAttestations:      pubKeyAttestations,
		maxConcurrentExecutions: DefaultMaxConcurrentExecutions,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.execSem = semaphore.NewWeighted(s.maxConcurrentExecutions)
	return s
}

// Handler returns the HTTP handler for the enclave server.
// This is useful for wrapping the server with middleware (e.g. in tests).
func (s *enclaveServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/publicKeys", s.handleGetPublicKeys)
	mux.HandleFunc("POST /config", s.handleSetConfig)
	mux.HandleFunc("PATCH /config", s.handleUpdateConfig)
	mux.HandleFunc("POST "+types.SettingsPath, s.handleInjectSettings)
	mux.HandleFunc("/requests", s.handleExecute)
	mux.HandleFunc("GET "+types.MemoryPath, s.handleMemory)
	return mux
}

func (s *enclaveServer) Start(listener net.Listener) error {
	if err := http.Serve(listener, s.Handler()); err != nil {
		s.logger.Fatalf("server error: %v", err)
	}

	return nil
}

// handleGetPublicKeys handles the /publicKeys endpoint.
// It returns an attested payload containing its current public key for the given request.
// If a requestID query parameter is provided, the keychain maps that request to a specific
// keypair, ensuring all capability nodes get the same key for the same request even during rotation.
func (s *enclaveServer) handleGetPublicKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, fmt.Sprintf("method not allowed: %v", r.Method), http.StatusMethodNotAllowed)
		return
	}

	s.configLock.Lock()
	config := s.config.Copy()
	s.configLock.Unlock()

	if config.IsZero() {
		http.Error(w, "enclave config not set", http.StatusServiceUnavailable)
		return
	}

	// Parse requestID from query params if present. When provided, we return
	// a single keypair pinned to this request to avoid rotation race conditions.
	// Accepts both hex encoding (new clients) and base64 encoding (old clients)
	// for backwards compatibility.
	var keypairs []keychain.Keypair
	requestIDParam := r.URL.Query().Get("requestID")
	if requestIDParam != "" {
		requestIDBytes, err := hex.DecodeString(requestIDParam)
		if err != nil || len(requestIDBytes) != 32 {
			// Fall back to base64 for backwards compatibility with older clients.
			requestIDBytes, err = base64.StdEncoding.DecodeString(requestIDParam)
			if err != nil || len(requestIDBytes) != 32 {
				http.Error(w, "invalid requestID: must be 32 bytes hex-encoded or base64-encoded", http.StatusBadRequest)
				return
			}
		}
		var requestID [32]byte
		copy(requestID[:], requestIDBytes)

		kp, err := s.keychain.GetKeyPairForRequest(requestID)
		if err != nil {
			http.Error(w, fmt.Sprintf("error retrieving keypair for request: %v", err), http.StatusInternalServerError)
			return
		}
		keypairs = []keychain.Keypair{kp}
	} else {
		var err error
		keypairs, err = s.keychain.GetKeyPairs()
		if err != nil {
			http.Error(w, fmt.Sprintf("error retrieving keypairs: %v", err), http.StatusInternalServerError)
			return
		}
	}

	if len(keypairs) == 0 {
		http.Error(w, "no keypairs found", http.StatusNotFound)
		return
	}

	var publicKeys [][]byte
	var creationTimes []time.Time
	var ttls []time.Duration
	for _, keypair := range keypairs {
		publicKeys = append(publicKeys, keypair.Public())
		creationTimes = append(creationTimes, keypair.CreationTime())
		ttls = append(ttls, keypair.TTL())
	}

	resp := types.PublicKeyResponse{
		PublicKeys:    publicKeys,
		CreationTimes: creationTimes,
		TTLs:          ttls,
		Config:        config,
	}
	att, err := s.attestPublicKeys(resp.PublicKeyHash())
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating attestation: %v", err), http.StatusInternalServerError)
		return
	}
	resp.Attestation = att

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// attestPublicKeys returns an NSM attestation over the given /publicKeys
// content hash, serving repeated requests for the same content from the
// cache and collapsing concurrent misses into a single NSM call.
func (s *enclaveServer) attestPublicKeys(dataToAttest [32]byte) ([]byte, error) {
	// Fast path: cache hit.
	if att, ok := s.pubKeyAttestations.Get(dataToAttest); ok {
		return att, nil
	}
	v, err, _ := s.attestationGroup.Do(string(dataToAttest[:]), func() (any, error) {
		// Re-check the cache: a miss that arrives after a flight completes
		// leads a new flight even though the result was just cached.
		if att, ok := s.pubKeyAttestations.Get(dataToAttest); ok {
			return att, nil
		}
		att, err := s.attestor.CreateAttestation(dataToAttest[:])
		if err != nil {
			return nil, err
		}
		s.pubKeyAttestations.Set(dataToAttest, att, nil)
		return att, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
}

// handleMemory handles the GET /memory endpoint. It reports the enclave process's
// memory usage as read from the Go runtime, rounded to the nearest megabyte. The
// megabyte granularity is deliberate: it is a coarse operational signal, and the
// rounding limits the resolution of any memory-based side channel into the
// confidential workload.
func (s *enclaveServer) handleMemory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, fmt.Sprintf("method not allowed: %v", r.Method), http.StatusMethodNotAllowed)
		return
	}

	resp := types.MemoryEstimateResponse{
		UsedMB: bytesToMB(readRuntimeMemoryBytes()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// readRuntimeMemoryBytes returns the total memory mapped by the Go runtime, in
// bytes. It uses runtime/metrics rather than runtime.ReadMemStats to avoid the
// stop-the-world pause the latter incurs, since this endpoint may be polled
// frequently.
func readRuntimeMemoryBytes() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindUint64 {
		return samples[0].Value.Uint64()
	}
	return 0
}

// bytesToMB rounds a byte count to the nearest megabyte.
func bytesToMB(b uint64) uint64 {
	const mb = 1024 * 1024
	return (b + mb/2) / mb
}

// handleSetConfig handles the /config endpoint.
// It sets the enclave configuration and returns an attestation of the current config.
func (s *enclaveServer) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	s.configLock.Lock()
	defer s.configLock.Unlock()
	if r.Method != http.MethodPost {
		http.Error(w, fmt.Sprintf("method not allowed: %v", r.Method), http.StatusMethodNotAllowed)
		return
	}

	if s.configSet && !s.allowReconfig {
		http.Error(w, "config has already been set and cannot be changed", http.StatusConflict)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req types.ConfigRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse config request: %v", err), http.StatusBadRequest)
		return
	}
	var newConfig types.EnclaveConfig
	if err := json.Unmarshal(req.Config, &newConfig); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse new config: %v", err), http.StatusBadRequest)
		return
	}

	s.config = newConfig
	s.configSet = true

	// Notify the app if it supports config updates (e.g., to propagate
	// MasterPublicKey and threshold to the remote dispatcher for TDH2).
	type configurable interface {
		OnConfigUpdate(types.EnclaveConfig)
	}
	if c, ok := s.app.(configurable); ok {
		c.OnConfigUpdate(newConfig)
	}

	resp := types.SetConfigResponse{
		Config: newConfig,
	}
	att, err := s.attestor.CreateAttestation(resp.UserDataHash())
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating attestation: %v", err), http.StatusInternalServerError)
		return
	}
	resp.Attestation = att

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleInjectSettings handles POST /settings. The host-side settings injector
// pushes runtime config + secrets here over vsock (it is deliberately NOT
// proxied to the external network by the host). It carries the ed25519 storage
// key the enclave uses to authenticate workflow-binary fetches plus endpoints
// and fetcher tunables; the app holds them in memory and rebuilds its storage
// fetcher. Nothing lands in the measured image, so values can change without
// re-measuring the enclave.
func (s *enclaveServer) handleInjectSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, fmt.Sprintf("method not allowed: %v", r.Method), http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req types.SettingsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse settings request: %v", err), http.StatusBadRequest)
		return
	}
	if req == (types.SettingsRequest{}) {
		http.Error(w, "settings request is empty", http.StatusBadRequest)
		return
	}

	type settingsReceiver interface {
		InjectSettings(types.SettingsRequest) error
	}
	c, ok := s.app.(settingsReceiver)
	if !ok {
		http.Error(w, "app does not accept settings", http.StatusNotImplemented)
		return
	}
	if err := c.InjectSettings(req); err != nil {
		http.Error(w, fmt.Sprintf("injecting settings: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateConfig handles PATCH on the /config endpoint. It accepts a config-update
// vote signed by a current signer; once F+1 unique current signers have voted for the
// same config, the enclave applies it.
func (s *enclaveServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	s.configLock.Lock()
	defer s.configLock.Unlock()

	if !s.configSet {
		http.Error(w, "config has not been initialized, cannot update", http.StatusConflict)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req types.UpdateConfigRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse config update request: %v", err), http.StatusBadRequest)
		return
	}
	var newConfig types.EnclaveConfig
	if err := json.Unmarshal(req.Config, &newConfig); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse proposed config: %v", err), http.StatusBadRequest)
		return
	}

	// Verify the vote was signed by a current signer.
	newHash := newConfig.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputeConfigUpdatePrefix(), newHash[:])
	signer, err := s.verifier.VerifySignature(prefixedHash, req.Signature, s.config.Signers)
	if err != nil {
		http.Error(w, fmt.Sprintf("config update signature verification failed: %v", err), http.StatusBadRequest)
		return
	}

	// If the proposed config already matches the current one there is nothing to
	// change; acknowledge it as applied without recording a vote or re-running the
	// config-update hook.
	currentHash := s.config.Hash()
	if newHash == currentHash {
		setConfigResp := types.SetConfigResponse{Config: s.config}
		att, err := s.attestor.CreateAttestation(setConfigResp.UserDataHash())
		if err != nil {
			http.Error(w, fmt.Sprintf("error creating attestation: %v", err), http.StatusInternalServerError)
			return
		}
		required := int(s.config.F) + 1
		resp := types.UpdateConfigResponse{
			Applied:          true,
			Config:           s.config,
			SignersCollected: required,
			SignersRequired:  required,
			Attestation:      att,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Record the vote for this proposed config.
	votes, ok := s.pendingConfigVotes.Get(newHash)
	if !ok {
		votes = make(map[[32]byte]struct{})
	}
	votes[sha256.Sum256(signer)] = struct{}{}
	s.pendingConfigVotes.Set(newHash, votes, nil)

	required := int(s.config.F) + 1
	resp := types.UpdateConfigResponse{
		Config:           newConfig,
		SignersCollected: len(votes),
		SignersRequired:  required,
	}

	if len(votes) < required {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Quorum reached: apply the new config and clear stale votes.
	s.config = newConfig
	s.pendingConfigVotes.Flush()

	// Notify the app if it supports config updates (e.g., to propagate
	// MasterPublicKey and threshold to the remote dispatcher for TDH2).
	type configurable interface {
		OnConfigUpdate(types.EnclaveConfig)
	}
	if c, ok := s.app.(configurable); ok {
		c.OnConfigUpdate(newConfig)
	}

	resp.Applied = true
	setConfigResp := types.SetConfigResponse{Config: newConfig}
	att, err := s.attestor.CreateAttestation(setConfigResp.UserDataHash())
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating attestation: %v", err), http.StatusInternalServerError)
		return
	}
	resp.Attestation = att

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleExecute handles the /requests endpoint.
// It validates incoming signed compute requests, produces plaintext secrets from their encrypted decryption shares,
// and executes the requests inside the injected enclave application.
func (s *enclaveServer) handleExecute(w http.ResponseWriter, r *http.Request) {
	// Create a response emitter to collect metrics for the response payload.
	responseEmitter := NewResponseEmitter()
	startTime := time.Now()
	responseEmitter.Emit("request_started", map[string]any{
		"endpoint": "execute",
	})

	if r.Method != http.MethodPost {
		responseEmitter.WriteErrorResponse(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bound concurrent executions so a burst cannot exhaust the enclave's fixed
	// memory and wedge it. Reject fast with 429 instead of running unbounded work;
	// the host is expected to queue/retry on this signal, not push harder.
	if !s.execSem.TryAcquire(1) {
		responseEmitter.Emit("execution_rejected_at_capacity", map[string]any{
			"max_concurrent": s.maxConcurrentExecutions,
		})
		responseEmitter.WriteErrorResponse(w, "enclave at capacity: too many concurrent executions", http.StatusTooManyRequests)
		return
	}
	defer s.execSem.Release(1)

	s.configLock.Lock()
	config := s.config.Copy()
	s.configLock.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		responseEmitter.WriteErrorResponse(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var reqs []types.SignedComputeRequest
	if err := json.Unmarshal(body, &reqs); err != nil {
		responseEmitter.WriteErrorResponse(w, "invalid json", http.StatusBadRequest)
		return
	}

	if len(reqs) == 0 {
		responseEmitter.WriteErrorResponse(w, "empty request batch", http.StatusBadRequest)
		return
	}

	// Validate each request signature & hash.
	sigVerifyStart := time.Now()
	signerSet := make(map[[32]byte]struct{})
	hash := reqs[0].Hash()
	for i, req := range reqs {
		reqHash := req.Hash()
		if !bytes.Equal(hash[:], reqHash[:]) {
			responseEmitter.WriteErrorResponse(w, fmt.Sprintf("request hash mismatch for request %d: have %x, want %x", i, reqHash, hash), http.StatusBadRequest)
			return
		}
		prefixedRequestHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), reqHash[:])

		signer, err := s.verifier.VerifySignature(prefixedRequestHash[:], req.Signature, config.Signers)
		if err != nil {
			responseEmitter.WriteErrorResponse(w, fmt.Sprintf("signature verification failed for request %d: %v", i, err), http.StatusBadRequest)
			return
		}
		signerSet[sha256.Sum256(signer)] = struct{}{}
	}
	responseEmitter.Emit("signature_verification_completed", map[string]any{
		"duration_seconds": time.Since(sigVerifyStart).Seconds(),
		"num_signatures":   len(reqs),
	})

	// Need F+1 requests by unique signers to process the batch.
	if len(signerSet) < int(config.F)+1 {
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("not enough requests by unique signers to reach quorum, got %d, need %d", len(signerSet), int(config.F)+1), http.StatusBadRequest)
		return
	}

	// Prevent multiple concurrent requests with the same hash from being processed, which could cause replay attacks and double execution.
	s.reqsLock.RLock()
	if _, exists := s.inProgressReqs.Get(hash); exists {
		s.reqsLock.RUnlock()
		responseEmitter.WriteErrorResponse(w, "request is already being processed", http.StatusConflict)
		return
	}
	s.reqsLock.RUnlock()

	// Mark this request hash as in-progress to prevent concurrent processing of the same request.
	// Free the request hash from the in-progress cache when the request is done processing, even if there are errors, to allow retries.
	s.reqsLock.Lock()
	s.inProgressReqs.Set(hash, struct{}{}, nil)
	s.reqsLock.Unlock()
	defer func() {
		s.reqsLock.Lock()
		s.inProgressReqs.Delete(hash)
		s.reqsLock.Unlock()
	}()

	// Check if this request hash has already been executed to prevent replay attacks.
	s.reqsLock.RLock()
	if _, exists := s.executedReqs.Get(hash); exists {
		s.reqsLock.RUnlock()
		responseEmitter.WriteErrorResponse(w, "replay detected: request hash has already been executed", http.StatusConflict)
		return
	}
	s.reqsLock.RUnlock()

	// All requests are valid at this point, use the first request for processing.
	req := reqs[0]

	// Now that we have the request, add request_id to metrics.
	responseEmitter.Emit("request_id", map[string]any{
		"request_id": fmt.Sprintf("%x", req.RequestID),
	})

	if len(req.Ciphertexts) != len(req.CiphertextNames) {
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("number of ciphertexts (%d) does not match number of ciphertext names (%d)", len(req.Ciphertexts), len(req.CiphertextNames)), http.StatusBadRequest)
		return
	}

	if len(req.AppID) == 0 {
		responseEmitter.WriteErrorResponse(w, "missing AppID in request", http.StatusBadRequest)
		return
	}

	if len(req.Version) == 0 {
		responseEmitter.WriteErrorResponse(w, "missing Version in request", http.StatusBadRequest)
		return
	}

	// Retrieve the corresponding ephemeral keypair for this request.
	keypair, err := s.keychain.GetKeyPair(req.EnclaveEphemeralPublicKey)
	if err != nil {
		responseEmitter.Emit("keypair_not_found", map[string]any{
			"error": err.Error(),
		})
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("failed to retrieve keypair for request: %v", err), http.StatusBadRequest)
		return
	}

	sharesCombineStart := time.Now()
	var secretsMap map[string][]byte
	var lastErr error
	for nodeIdx, nodeReq := range reqs {
		nodeSecrets := make(map[string][]byte, len(req.Ciphertexts))
		success := true
		// EncryptedDecryptionKeyShares is not covered by ComputeRequest.Hash(), so a
		// signed request can carry a shares slice shorter than reqs[0].Ciphertexts.
		// Guard against indexing out of range and skip such nodes.
		if len(nodeReq.EncryptedDecryptionKeyShares) != len(req.Ciphertexts) {
			lastErr = fmt.Errorf("node %d has %d sets of encrypted decryption key shares, expected %d", nodeIdx, len(nodeReq.EncryptedDecryptionKeyShares), len(req.Ciphertexts))
			s.logger.Printf("%v", lastErr)
			continue
		}
		for i, ciphertext := range req.Ciphertexts {
			encryptedShares := nodeReq.EncryptedDecryptionKeyShares[i]
			var decryptedShares [][]byte

			for _, encryptedShare := range encryptedShares {
				decryptedShare, err := keypair.Decrypt(encryptedShare)
				if err != nil {
					continue
				}
				decryptedShares = append(decryptedShares, decryptedShare)
			}

			secret, err := s.combiner.AggregateShares(ciphertext, decryptedShares, config.MasterPublicKey, int(config.T))
			if err != nil {
				lastErr = err
				s.logger.Printf("shares from node %d failed aggregation for ciphertext %d: %v", nodeIdx, i, err)
				success = false
				break
			}
			nodeSecrets[req.CiphertextNames[i]] = secret
		}
		if success {
			secretsMap = nodeSecrets
			break
		}
	}
	if secretsMap == nil {
		responseEmitter.Emit("share_aggregation_failed", map[string]any{
			"error": lastErr.Error(),
		})
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("no node's shares produced valid decryption: %v", lastErr), http.StatusInternalServerError)
		return
	}
	responseEmitter.Emit("shares_combining_completed", map[string]any{
		"duration_seconds": time.Since(sharesCombineStart).Seconds(),
		"num_ciphertexts":  len(req.Ciphertexts),
	})

	appExecStart := time.Now()
	// Forward the full F+1 signed batch to the app; confidential-workflows relays it
	// to the relay DON as the authorization for any secrets requests.
	execResp, execErr := s.app.Execute(req.RequestID, req.AppID, req.PublicData, secretsMap, responseEmitter, reqs...)
	responseEmitter.Emit("app_execution_completed", map[string]any{
		"duration_seconds": time.Since(appExecStart).Seconds(),
	})
	if execErr != nil {
		responseEmitter.Emit("app_execution_failed", map[string]any{
			"error": execErr,
		})
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("error executing enclave app request: %v", execErr), http.StatusInternalServerError)
		return
	}

	// Emit request_completed before building the response. The outcome attribute
	// lets success and error share one request_completed metric.
	responseEmitter.Emit("request_completed", map[string]any{
		"endpoint":         "execute",
		"outcome":          "success",
		"duration_seconds": time.Since(startTime).Seconds(),
	})

	resp := types.ExecuteResponse{
		RequestID:            req.RequestID,
		ApplicationRequestID: req.ApplicationRequestID,
		RequestHash:          hash,
		Config:               config,
		Output:               execResp,
	}
	att, err := s.attestor.CreateAttestation(resp.UserDataHash(req.Version))
	if err != nil {
		responseEmitter.Emit("attestation_creation_failed", map[string]any{
			"endpoint": "execute",
			"error":    err.Error(),
		})
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("error creating attestation: %v", err), http.StatusInternalServerError)
		return
	}
	resp.Metrics = responseEmitter.GetMetrics()
	resp.MetricEvents = responseEmitter.GetMetricEvents()
	resp.Attestation = att

	respBytes, err := json.Marshal(resp)
	if err != nil {
		responseEmitter.WriteErrorResponse(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}

	// Record successful executions so identical signed requests can be rejected as replays.
	s.reqsLock.Lock()
	s.executedReqs.Set(hash, struct{}{}, nil)
	s.reqsLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBytes)
}
