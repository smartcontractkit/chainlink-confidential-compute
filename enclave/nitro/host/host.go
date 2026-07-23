package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	confhttptypes "github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-http/types"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

var (
	vsockPrefix     = "http://localhost"
	cacheDefaultTTL = types.InboundProxyRequestCacheTTL
	cacheGCInterval = 10 * time.Minute
)

var (
	httpPort       = flag.Int("port", 8080, "HTTP port to listen on")
	configHttpPort = flag.Int("config-port", 8081, "HTTP port for config endpoint (localhost only)")
	enclavePort    = flag.Int("enclave-port", 5000, "VSOCK port the enclave is listening on")
	enclaveCID     = flag.Int("enclave-cid", 16, "VSOCK CID of the enclave")
	quorumTimeout  = flag.Duration("quorum-timeout", types.QuorumTimeout, "Timeout for waiting for quorum to be reached")
	// requireBFTQuorum raises the batch quorum threshold from f+1 (one honest
	// node) to 2f+1 (a BFT supermajority). Reads REQUIRE_BFT_QUORUM.
	requireBFTQuorum = flag.Bool("require-bft-quorum", os.Getenv("REQUIRE_BFT_QUORUM") == "true", "require a 2f+1 BFT quorum instead of f+1. Reads REQUIRE_BFT_QUORUM.")
	storageKey       = flag.String("storage-key", os.Getenv("STORAGE_KEY"), "hex ed25519 CRE storage-service key to inject into the enclave over vsock (from a K8s secret). Reads STORAGE_KEY.")
	storageSvcURL    = flag.String("storage-service-url", os.Getenv("STORAGE_SERVICE_URL"), "CRE storage-service gRPC address (host:port) to inject into the enclave. Reads STORAGE_SERVICE_URL.")
	storageSvcTLS    = flag.Bool("storage-service-tls", os.Getenv("STORAGE_SERVICE_TLS") != "false", "whether the enclave should use TLS for the storage-service connection. Reads STORAGE_SERVICE_TLS (default true).")
	gatewayURL       = flag.String("gateway-url", os.Getenv("GATEWAY_URL"), "Gateway URL(s) for remote dispatch to inject into the enclave. Comma-separated for round-robin failover across multiple gateways. Empty leaves the enclave local-only. Reads GATEWAY_URL.")

	maxBinarySize      = flag.Int64("max-binary-size", envInt64("MAX_BINARY_SIZE"), "max workflow-binary size in bytes the enclave accepts from storage. 0 uses the enclave default. Reads MAX_BINARY_SIZE.")
	binaryFetchTimeout = flag.Duration("binary-fetch-timeout", envDuration("BINARY_FETCH_TIMEOUT"), "per-fetch timeout for downloading a workflow binary (e.g. 90s). 0 uses the enclave default. Reads BINARY_FETCH_TIMEOUT.")
	maxCacheBytes      = flag.Int64("max-cache-bytes", envInt64("MAX_CACHE_BYTES"), "size bound in bytes of the enclave's verified-binary LRU cache. 0 uses the enclave default. Reads MAX_CACHE_BYTES.")

	// settingsJSON, when set, overrides all the individual settings flags above:
	// the host forwards this raw JSON to the enclave verbatim instead of building
	// the payload from the typed flags. The enclave app owns the schema. Empty
	// falls back to the individual flags. Reads ENCLAVE_SETTINGS (a JSON object).
	settingsJSON = flag.String("settings", os.Getenv("ENCLAVE_SETTINGS"), "raw JSON settings to inject into the enclave over vsock, forwarded verbatim. Overrides the individual settings flags when set. Reads ENCLAVE_SETTINGS.")

	// readHeaderTimeout bounds how long a client may take to send request headers.
	readHeaderTimeout = flag.Duration("read-header-timeout", 30*time.Second, "Max duration allowed to read request headers")
	// readTimeout bounds the total time to read a request, including a body up to
	// types.MaxInboundRequestBodyBytes (64 MiB).
	readTimeout = flag.Duration("read-timeout", 2*time.Minute, "Max duration allowed to read the full request")
	// writeTimeout bounds handler execution plus response writing.
	writeTimeout = flag.Duration("write-timeout", 10*time.Minute, "Max duration allowed to write the response")
	// idleTimeout bounds how long an idle keep-alive connection is kept open.
	idleTimeout = flag.Duration("idle-timeout", 2*time.Minute, "Max duration to keep idle keep-alive connections open")
	// maxHeaderBytes caps the accepted request header size (1 MiB).
	maxHeaderBytes = flag.Int("max-header-bytes", 1<<20, "Max size of request headers in bytes (default 1 MiB)")
)

// envInt64 returns the int64 value of an env var, or 0 if unset or unparsable.
func envInt64(key string) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

// envDuration returns the time.Duration value of an env var (e.g. "90s"), or 0
// if unset or unparsable.
func envDuration(key string) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 0
}

// `hostServer` provides an untrusted proxy for AWS Nitro Enclaves.
// It blocks incoming requests until a threshold of identical requests are reached,
// forwards validated requests to the enclave over VSOCK, and caches responses.
type hostServer struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	enclaveClient        *http.Client
	config               types.EnclaveConfig
	configMutex          sync.RWMutex
	processRequestMutex  sync.Mutex
	pendingRequestsCache *util.Cache[*batchRequest]
	responseCache        *util.Cache[*types.ExecuteResponse]
	verifier             signatureverifier.SignatureVerifier
	logger               cllogger.SugaredLogger
}

type batchRequest struct {
	requests          []types.SignedComputeRequest
	responseCh        []chan *batchResponse
	signersSeen       map[string]bool // track unique signers by their public keys
	createdAt         time.Time       // track when the batch was created for timeout detection
	processingRequest bool            // true when quorum reached and batch is being processed
	doneCh            chan struct{}   // closed when batch processing completes (success or failure)
	doneOnce          sync.Once       // ensures doneCh is closed exactly once
}

// signers returns the hex-encoded sender public keys that contributed to the
// batch, sorted for deterministic log output.
func (br *batchRequest) signers() []string {
	return slices.Sorted(maps.Keys(br.signersSeen))
}

type batchResponse struct {
	response *types.ExecuteResponse
	err      error
}

func logPublicData(reqLog cllogger.SugaredLogger, appID string, publicData []byte) {
	switch appID {
	case types.AppIDConfidentialHTTP:
		var req confhttptypes.Request
		if err := proto.Unmarshal(publicData, &req); err != nil {
			reqLog.Warnw("failed to decode publicData",
				"event", "PUBLIC_DATA_DECODE_ERR",
				"appID", appID,
				"publicDataLen", len(publicData),
				"error", err)
			return
		}

		bodyKind := "none"
		bodyLen := 0
		switch body := req.GetBody().(type) {
		case *confhttptypes.Request_BodyString:
			bodyKind = "string"
			bodyLen = len(body.BodyString)
		case *confhttptypes.Request_BodyBytes:
			bodyKind = "bytes"
			bodyLen = len(body.BodyBytes)
		}

		timeout := ""
		if req.GetTimeout() != nil {
			timeout = req.GetTimeout().AsDuration().String()
		}

		reqLog.Infow("decoded publicData",
			"event", "PUBLIC_DATA",
			"appID", appID,
			"publicDataLen", len(publicData),
			"publicDataType", "confidential_http_request",
			"url", req.GetUrl(),
			"method", req.GetMethod(),
			"bodyKind", bodyKind,
			"bodyLen", bodyLen,
			"headerNames", slices.Sorted(maps.Keys(req.GetMultiHeaders())),
			"templatePublicValueKeys", slices.Sorted(maps.Keys(req.GetTemplatePublicValues())),
			"customRootCACertPEMLen", len(req.GetCustomRootCaCertPem()),
			"timeout", timeout,
			"encryptOutput", req.GetEncryptOutput())

	case types.AppIDConfidentialWorkflows:
		var execution confworkflowtypes.WorkflowExecution
		if err := proto.Unmarshal(publicData, &execution); err != nil {
			reqLog.Warnw("failed to decode publicData",
				"event", "PUBLIC_DATA_DECODE_ERR",
				"appID", appID,
				"publicDataLen", len(publicData),
				"error", err)
			return
		}

		executeRequestKind := "unset"
		executeRequestConfigLen := 0
		var maxResponseSize uint64
		fields := []any{
			"event", "PUBLIC_DATA",
			"appID", appID,
			"publicDataLen", len(publicData),
			"publicDataType", "workflow_execution",
			"workflowID", execution.GetWorkflowId(),
			"executionID", execution.GetExecutionId(),
			"owner", execution.GetOwner(),
			"orgID", execution.GetOrgId(),
			"binaryURL", execution.GetBinaryUrl(),
			"binaryHash", hex.EncodeToString(execution.GetBinaryHash()),
			"requirementsPresent", execution.GetRequirements() != nil,
			"restrictionsPresent", execution.GetRestrictions() != nil,
		}

		if execReq := execution.GetSdkExecuteRequest(); execReq != nil {
			executeRequestConfigLen = len(execReq.GetConfig())
			maxResponseSize = execReq.GetMaxResponseSize()
			switch req := execReq.GetRequest().(type) {
			case *sdkpb.ExecuteRequest_Subscribe:
				executeRequestKind = "subscribe"
			case *sdkpb.ExecuteRequest_Trigger:
				executeRequestKind = "trigger"
				fields = append(fields, "triggerID", req.Trigger.GetId())
			case *sdkpb.ExecuteRequest_PreHook:
				executeRequestKind = "pre_hook"
				fields = append(fields, "triggerID", req.PreHook.GetId())
			}
		}

		fields = append(fields,
			"executeRequestKind", executeRequestKind,
			"executeRequestConfigLen", executeRequestConfigLen,
			"maxResponseSize", maxResponseSize)
		reqLog.Infow("decoded publicData", fields...)

	default:
		reqLog.Debugw("publicData decoder unavailable",
			"event", "PUBLIC_DATA_UNSUPPORTED",
			"appID", appID,
			"publicDataLen", len(publicData))
	}
}

func NewHostServer(ctx context.Context, clientOverride *http.Client) *hostServer {
	var client *http.Client
	if clientOverride == nil {
		// execute HTTP traffic over vsock to the enclave
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return vsock.Dial(uint32(*enclaveCID), uint32(*enclavePort), nil)
				},
			},
		}
	} else {
		client = clientOverride
	}

	ctx, cancel := context.WithCancel(ctx)
	return &hostServer{
		ctx:                  ctx,
		cancel:               cancel,
		enclaveClient:        client,
		pendingRequestsCache: util.NewCache[*batchRequest](&cacheDefaultTTL, &cacheGCInterval),
		responseCache:        util.NewCache[*types.ExecuteResponse](&cacheDefaultTTL, &cacheGCInterval),
		config:               types.EnclaveConfig{},
		verifier:             signatureverifier.NewEd25519SignatureVerifier(),
		// No-op by default so tests stay quiet; main injects the real logger.
		logger: cllogger.Sugared(cllogger.Nop()),
	}
}

// handlePublicKey handles the /publicKeys endpoint, which fetches an ephemeral public key for a request.
func (h *hostServer) handleGetPublicKeys(w http.ResponseWriter, r *http.Request) {
	arrivalTime := time.Now()

	logger := h.logger.With("remoteAddr", r.RemoteAddr)
	logger.Infow("publicKeys request arrived",
		"event", "RECV_PUBKEYS")

	if r.Method != http.MethodGet {
		logger.Warnw("publicKeys request rejected",
			"event", "REJECT_PUBKEYS",
			"reason", "method_not_allowed",
			"method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, vsockPrefix+"/publicKeys", nil)
	if err != nil {
		logger.Errorw("failed to create publicKeys request",
			"event", "PUBKEYS_ERR",
			"error", err)
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}
	// Forward requestID query parameter to the enclave so it can pin a keypair to this request.
	q := req.URL.Query()
	if requestID := r.URL.Query().Get("requestID"); requestID != "" {
		q.Set("requestID", requestID)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := h.enclaveClient.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			logger.Warnw("publicKeys client disconnected",
				"event", "CLIENT_DISCONNECT_PUBKEYS",
				"waitDuration", time.Since(arrivalTime).String())
			http.Error(w, "client disconnected", http.StatusRequestTimeout)
			return
		}
		logger.Errorw("failed to communicate with enclave for publicKeys",
			"event", "PUBKEYS_ERR",
			"error", err)
		http.Error(w, "failed to communicate with enclave", http.StatusInternalServerError)
		return
	}
	defer util.SafeClose(resp)

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Errorw("error copying publicKeys response",
			"event", "PUBKEYS_ERR",
			"error", err)
		return
	}

	logger.Infow("publicKeys response sent",
		"event", "RESPONSE_OK_PUBKEYS",
		"statusCode", resp.StatusCode,
		"waitDuration", time.Since(arrivalTime).String())
}

// handleMemory handles GET on the /memory endpoint, forwarding the request to the
// enclave over vsock and relaying its memory estimate. The estimate is produced
// inside the enclave; the host is a transparent proxy.
func (h *hostServer) handleMemory(w http.ResponseWriter, r *http.Request) {
	arrivalTime := time.Now()

	logger := h.logger.With("remoteAddr", r.RemoteAddr)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, vsockPrefix+types.MemoryPath, nil)
	if err != nil {
		logger.Errorw("failed to create memory request", "event", "MEMORY_ERR", "error", err)
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	resp, err := h.enclaveClient.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			http.Error(w, "client disconnected", http.StatusRequestTimeout)
			return
		}
		logger.Errorw("failed to communicate with enclave for memory", "event", "MEMORY_ERR", "error", err)
		http.Error(w, "failed to communicate with enclave", http.StatusInternalServerError)
		return
	}
	defer util.SafeClose(resp)

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Errorw("error copying memory response", "event", "MEMORY_ERR", "error", err)
		return
	}

	logger.Infow("memory response sent",
		"event", "RESPONSE_OK_MEMORY",
		"statusCode", resp.StatusCode,
		"waitDuration", time.Since(arrivalTime).String())
}

// handleSetConfig handles POST on the /config endpoint, which sets the enclave's
// configuration for the first time.
func (h *hostServer) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	h.proxyConfig(w, r, http.MethodPost, func(respBody []byte) error {
		var configResp types.SetConfigResponse
		if err := json.Unmarshal(respBody, &configResp); err != nil {
			return err
		}
		h.configMutex.Lock()
		h.config = configResp.Config
		h.configMutex.Unlock()
		h.logger.Infow("host updated local config", "T", configResp.Config.T, "F", configResp.Config.F)
		return nil
	})
}

// handleUpdateConfig handles PATCH on the /config endpoint, forwarding a signed
// config-update vote to the enclave. The enclave applies the new config once a
// quorum of current signers have voted; only then does the host adopt it locally.
func (h *hostServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	h.proxyConfig(w, r, http.MethodPatch, func(respBody []byte) error {
		var configResp types.UpdateConfigResponse
		if err := json.Unmarshal(respBody, &configResp); err != nil {
			return err
		}
		if configResp.Applied {
			h.configMutex.Lock()
			h.config = configResp.Config
			h.configMutex.Unlock()
			h.logger.Infow("host updated local config via quorum update", "T", configResp.Config.T, "F", configResp.Config.F)
		}
		return nil
	})
}

// handleInjectSettings proxies a POST /settings to the enclave over vsock.
// It is registered ONLY on the config port (127.0.0.1:config-port, where POST
// /config lives), never the public main port, so only a co-located settings
// service can reach it, not arbitrary callers.
func (h *hostServer) handleInjectSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, vsockPrefix+types.SettingsPath, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "failed to build request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.enclaveClient.Do(req)
	if err != nil {
		http.Error(w, "failed to reach enclave", http.StatusBadGateway)
		return
	}
	defer util.SafeClose(resp)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// injectSettings is the host-side "settings service": it POSTs the opaque
// settings JSON to the enclave's /settings endpoint over vsock. That endpoint is
// deliberately NOT exposed on the host's external HTTP ports, so the values only
// ever travel host->enclave over vsock, never the network. A Nitro EIF is
// measured, so environment endpoints (storage URL, gateway URL) can't be baked
// in and are injected here at runtime. The host forwards the payload verbatim;
// the enclave app owns the schema. Retries while the enclave is still booting.
func (h *hostServer) injectSettings(ctx context.Context, payload []byte) error {
	const (
		maxAttempts = 60
		retryDelay  = 2 * time.Second
	)
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, vsockPrefix+types.SettingsPath, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("building settings request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := h.enclaveClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
				slog.Info("injected storage credentials into enclave")
				return nil
			}
			lastErr = fmt.Errorf("enclave rejected credentials: status %d: %s", resp.StatusCode, string(body))
		}

		slog.Warn("credentials injection not yet accepted, retrying", "attempt", attempt, "error", lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	return fmt.Errorf("failed to inject credentials after %d attempts: %w", maxAttempts, lastErr)
}

// proxyConfig forwards a /config request to the enclave over vsock using the given
// method and relays the response. On a 200 response, applyConfig extracts the
// enclave's config from the body so the host can update its local copy.
func (h *hostServer) proxyConfig(w http.ResponseWriter, r *http.Request, method string, applyConfig func(respBody []byte) error) {
	logger := h.logger.With("method", method)

	r.Body = http.MaxBytesReader(w, r.Body, types.MaxInboundRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorw("failed to read request body", "error", err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	logger.Infow("config request invoked", "bodyLen", len(body))

	req, err := http.NewRequest(method, vsockPrefix+"/config", bytes.NewReader(body))
	if err != nil {
		logger.Errorw("failed to create request", "error", err)
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.enclaveClient.Do(req)
	if err != nil {
		logger.Errorw("failed to communicate with enclave", "error", err)
		http.Error(w, "failed to communicate with enclave", http.StatusInternalServerError)
		return
	}
	defer util.SafeClose(resp)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorw("failed to read response body", "error", err)
		http.Error(w, "failed to read response body", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode == http.StatusOK {
		if err := applyConfig(respBody); err != nil {
			logger.Errorw("failed to parse config response", "error", err)
			http.Error(w, "failed to parse response", http.StatusInternalServerError)
			return
		}
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err = w.Write(respBody); err != nil {
		logger.Errorw("error writing response", "error", err)
		return
	}
}

// quorumThreshold returns the number of identical signed requests required to
// dispatch a batch to the enclave. By default this is f+1 (at least one honest
// node); with --require-bft-quorum it is 2f+1 (a BFT supermajority).
func quorumThreshold(f uint32) int {
	if *requireBFTQuorum {
		return int(2*f + 1)
	}
	return int(f + 1)
}

// handleExecute handles the /requests endpoint, which executes a confidential HTTPS request through the enclave.
func (h *hostServer) handleExecute(w http.ResponseWriter, r *http.Request) {
	arrivalTime := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, types.MaxInboundRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	var execReq types.SignedComputeRequest
	if err := json.Unmarshal(body, &execReq); err != nil {
		h.logger.Errorw("failed to unmarshal request", "error", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Use the hash of the ComputeRequest as the cache key.
	// This ensures all requests that are processed together contain identical ComputeRequests.
	requestHash := execReq.Hash()
	requestHashHex := hex.EncodeToString(requestHash[:])
	requestIDHex := hex.EncodeToString(execReq.RequestID[:])
	ephemeralPKHex := hex.EncodeToString(execReq.EnclaveEphemeralPublicKey)
	sigFingerprint := hex.EncodeToString(execReq.Signature[:min(len(execReq.Signature), 8)])

	// Bind the request-scoped fields once so every subsequent log line for this
	// request carries them without re-listing them by hand. The signer is added
	// below once the signature has been verified.
	reqLog := h.logger.With(
		"requestID", requestIDHex,
		"requestHash", requestHashHex,
		"remoteAddr", r.RemoteAddr,
		"sigPrefix", sigFingerprint,
	)

	reqLog.Infow("request arrived",
		"event", "RECV",
		"applicationRequestID", execReq.ApplicationRequestID,
		"ephemeralPK", ephemeralPKHex,
		"bodyLen", len(body),
		"arrivalTime", arrivalTime.Format(time.RFC3339Nano))
	logPublicData(reqLog, execReq.AppID, execReq.PublicData)

	// Log hash input components for debugging hash divergence
	reqLog.Debugw("hash inputs",
		"event", "HASH_INPUTS",
		"applicationRequestID", execReq.ApplicationRequestID,
		"publicDataLen", len(execReq.PublicData),
		"ciphertextCount", len(execReq.Ciphertexts),
		"ciphertextNamesCount", len(execReq.CiphertextNames),
		"ephemeralPKLen", len(execReq.EnclaveEphemeralPublicKey),
		"masterPKLen", len(execReq.MasterPublicKey),
		"appID", execReq.AppID,
		"version", execReq.Version)

	// Log first 16 bytes of each ciphertext for divergence detection
	for i, ct := range execReq.Ciphertexts {
		prefix := ct
		if len(prefix) > 16 {
			prefix = prefix[:16]
		}
		reqLog.Debugw("ciphertext prefix",
			"event", "HASH_INPUTS",
			"ciphertextIndex", i,
			"ciphertextLen", len(ct),
			"prefix", fmt.Sprintf("%x", prefix))
	}

	// If T and F are both zero, the node is not configured. Reject the request.
	h.configMutex.RLock()
	t := h.config.T
	f := h.config.F
	h.configMutex.RUnlock()
	if t == 0 && f == 0 {
		reqLog.Warnw("rejecting request: not configured",
			"event", "REJECT",
			"reason", "not_configured",
			"T", t,
			"F", f)
		http.Error(w, "service not accepting requests (T and F are zero)", http.StatusServiceUnavailable)
		return
	}

	// Create a response channel for this specific request that corresponds
	// to the batch of requests for this request hash.
	responseCh := make(chan *batchResponse, 1)
	h.processRequestMutex.Lock()

	// Validate the domain separated hash of the request.
	var signer []byte
	prefixedRequestHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), requestHash[:])
	if signer, err = h.verifier.VerifySignature(prefixedRequestHash, execReq.Signature, h.config.Signers); err != nil {
		h.processRequestMutex.Unlock()
		reqLog.Warnw("rejecting request: signature verification failed",
			"event", "REJECT",
			"reason", "signature_verification_failed",
			"error", err)
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
		return
	}
	signerStr := hex.EncodeToString(signer)
	reqLog = reqLog.With("signer", signerStr)

	// If the response to this request is already cached, return it.
	if cachedResp, found := h.responseCache.Get(requestHash); found {
		h.processRequestMutex.Unlock()
		reqLog.Infow("cache hit",
			"event", "CACHE_HIT",
			"latencySinceArrival", time.Since(arrivalTime).String())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(cachedResp)
		if err != nil {
			reqLog.Errorw("error encoding cached response", "error", err)
		}
		return
	}

	// Log current state of pending and response caches for this requestID
	pendingCacheSize := h.pendingRequestsCache.Size()
	responseCacheSize := h.responseCache.Size()
	reqLog.Infow("cache miss",
		"event", "CACHE_MISS",
		"pendingCacheSize", pendingCacheSize,
		"responseCacheSize", responseCacheSize)

	// Add this request to the request batch for this request hash.
	br, exists := h.pendingRequestsCache.Get(requestHash)
	if !exists {
		reqLog.Infow("creating new batch",
			"event", "BATCH_NEW",
			"T", t,
			"F", f,
			"threshold", quorumThreshold(f))
		br = &batchRequest{
			requests:    make([]types.SignedComputeRequest, 0, len(h.config.Signers)),
			responseCh:  make([]chan *batchResponse, 0, len(h.config.Signers)),
			signersSeen: make(map[string]bool),
			createdAt:   time.Now(),
			doneCh:      make(chan struct{}),
		}

		// Start a timeout goroutine for this batch
		go h.handleQuorumTimeout(requestHash, f, br.doneCh)
	} else {
		reqLog.Infow("joining existing batch",
			"event", "BATCH_JOIN",
			"batchAge", time.Since(br.createdAt).String(),
			"currentBatchSize", len(br.requests),
			"threshold", quorumThreshold(f))
	}

	// If this signer already contributed to the batch, don't add a new signature
	// but still let them subscribe to the result for idempotency.
	if br.signersSeen[signerStr] {
		reqLog.Warnw("duplicate signer subscribing to batch result",
			"event", "DUPLICATE_SIGNER")
		br.responseCh = append(br.responseCh, responseCh)
		h.pendingRequestsCache.Set(requestHash, br, nil)
		h.processRequestMutex.Unlock()
	} else {
		br.signersSeen[signerStr] = true

		// Add the request to the batch.
		br.requests = append(br.requests, execReq)
		br.responseCh = append(br.responseCh, responseCh)

		// Check if we've reached quorum threshold while still holding the lock
		// to prevent race with timeout handler. The equality check ensures that
		// only the request that reaches exactly the threshold triggers processing;
		// subsequent requests will not re-trigger since len > threshold.
		threshold := quorumThreshold(f)
		shouldProcess := len(br.requests) == threshold
		if shouldProcess {
			br.processingRequest = true
		}

		reqLog.Debugw("batch state",
			"event", "BATCH_STATE",
			"batchSize", len(br.requests),
			"threshold", threshold,
			"shouldProcess", shouldProcess,
			"processingRequest", br.processingRequest)

		h.pendingRequestsCache.Set(requestHash, br, nil)
		requests := make([]types.SignedComputeRequest, len(br.requests))
		copy(requests, br.requests)
		// Snapshot the batch's sender public keys while we hold the lock.
		signers := br.signers()

		h.processRequestMutex.Unlock()

		if shouldProcess {
			reqLog.Infow("quorum reached, dispatching to enclave",
				"event", "QUORUM",
				"signers", signers,
				"signatureCount", len(requests))
			go func() {
				enclaveStart := time.Now()
				resp, err := h.processBatch(requests)
				enclaveDuration := time.Since(enclaveStart)
				if err != nil {
					reqLog.Errorw("enclave execution failed",
						"event", "ENCLAVE_ERR",
						"signers", signers,
						"enclaveDuration", enclaveDuration.String(),
						"error", err)
				} else {
					reqLog.Infow("enclave execution succeeded",
						"event", "ENCLAVE_OK",
						"signers", signers,
						"enclaveDuration", enclaveDuration.String())
				}
				h.completeBatch(requestHash, resp, err)
			}()
		}
	}

	// Wait for the response or a client disconnect.
	select {
	case batchResp := <-responseCh:
		waitDuration := time.Since(arrivalTime)
		if batchResp.err != nil {
			reqLog.Errorw("response error",
				"event", "RESPONSE_ERR",
				"waitDuration", waitDuration.String(),
				"error", batchResp.err)
			http.Error(w, fmt.Sprintf("error for request ID %x: %s", execReq.RequestID, batchResp.err), http.StatusInternalServerError)
			return
		}
		reqLog.Infow("response sent",
			"event", "RESPONSE_OK",
			"waitDuration", waitDuration.String())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(batchResp.response); err != nil {
			reqLog.Errorw("error encoding response", "error", err)
		}
	case <-r.Context().Done():
		waitDuration := time.Since(arrivalTime)
		reqLog.Warnw("client disconnected",
			"event", "CLIENT_DISCONNECT",
			"waitDuration", waitDuration.String())
		http.Error(w, "client disconnected", http.StatusRequestTimeout)
	}
}

// processBatch sends a batch of requests to the host's enclave for execution.
func (h *hostServer) processBatch(reqs []types.SignedComputeRequest) (*types.ExecuteResponse, error) {
	body, err := json.Marshal(reqs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch of requests: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, vsockPrefix+"/requests", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := h.enclaveClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to communicate with enclave: %w", err)
	}
	defer util.SafeClose(resp)
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("enclave returned error: %s (no message provided)", resp.Status)
		}
		return nil, fmt.Errorf("enclave returned error: %s - %s", resp.Status, string(body))
	}

	var execResp types.ExecuteResponse
	if err := json.NewDecoder(resp.Body).Decode(&execResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &execResp, nil
}

// notifyWaiters sends a response to all waiting channels for a batch.
// Must be called while holding processRequestMutex.
func (h *hostServer) notifyWaiters(br *batchRequest, resp *types.ExecuteResponse, err error) {
	notified := 0
	dropped := 0
	for _, ch := range br.responseCh {
		select {
		case ch <- &batchResponse{response: resp, err: err}:
			notified++
		default:
			dropped++
			h.logger.Warnw("response channel full, dropping response", "event", "NOTIFY_DROP")
		}
	}
	h.logger.Infow("waiters notified",
		"event", "NOTIFY",
		"signers", br.signers(),
		"notified", notified,
		"dropped", dropped,
		"totalWaiters", len(br.responseCh),
		"success", err == nil)
}

// completeBatch is called when batch processing finishes (success or error).
// It signals the timeout goroutine to exit, notifies all waiting channels, and cleans up.
func (h *hostServer) completeBatch(requestHash [32]byte, resp *types.ExecuteResponse, err error) {
	requestHashHex := hex.EncodeToString(requestHash[:])
	logger := h.logger.With("requestHash", requestHashHex)
	h.processRequestMutex.Lock()
	defer h.processRequestMutex.Unlock()

	br, exists := h.pendingRequestsCache.Get(requestHash)
	if !exists {
		logger.Infow("batch no longer in pending cache",
			"event", "COMPLETE_BATCH",
			"reason", "already_completed_or_timed_out")
		return
	}

	logger.Infow("completing batch",
		"event", "COMPLETE_BATCH",
		"signers", br.signers(),
		"waitersCount", len(br.responseCh),
		"batchAge", time.Since(br.createdAt).String(),
		"success", err == nil)

	br.doneOnce.Do(func() { close(br.doneCh) })
	h.notifyWaiters(br, resp, err)

	if resp != nil {
		h.responseCache.Set(requestHash, resp, nil)
		logger.Infow("response cached",
			"event", "CACHE_SET",
			"responseCacheSize", h.responseCache.Size())
	}
	h.pendingRequestsCache.Delete(requestHash)
}

// failBatchIfNotProcessed is called by the timeout handler when quorum isn't reached in time
// or when the server is shutting down.
// Returns true if the batch was failed, false if it was already completed or being processed.
func (h *hostServer) failBatchIfNotProcessed(requestHash [32]byte, f uint32, isShutdown bool) bool {
	requestHashHex := hex.EncodeToString(requestHash[:])
	logger := h.logger.With("requestHash", requestHashHex)
	h.processRequestMutex.Lock()
	defer h.processRequestMutex.Unlock()

	br, exists := h.pendingRequestsCache.Get(requestHash)
	if !exists || br.processingRequest {
		logger.Debugw("timeout skipped: batch already handled",
			"event", "TIMEOUT_SKIP",
			"exists", exists,
			"processingRequest", exists && br.processingRequest)
		return false
	}

	threshold := quorumThreshold(f)
	received := len(br.requests)

	// Log which signers we did receive
	var signersList []string
	for signer := range br.signersSeen {
		signersList = append(signersList, signer)
	}

	var batchErr error
	if isShutdown {
		batchErr = fmt.Errorf("server_shutdown: request cancelled due to server shutdown")
		logger.Warnw("batch failed: server shutdown",
			"event", "TIMEOUT_FAIL",
			"reason", "shutdown",
			"received", received,
			"threshold", threshold,
			"batchAge", time.Since(br.createdAt).String(),
			"signers", signersList)
	} else {
		batchErr = fmt.Errorf("%s: received %d of %d required signatures within %v", types.ErrQuorumTimeout, received, threshold, *quorumTimeout)
		logger.Warnw("batch failed: quorum timeout",
			"event", "TIMEOUT_FAIL",
			"reason", types.ErrQuorumTimeout,
			"received", received,
			"threshold", threshold,
			"batchAge", time.Since(br.createdAt).String(),
			"timeout", quorumTimeout.String(),
			"signers", signersList)
	}

	h.notifyWaiters(br, nil, batchErr)
	h.pendingRequestsCache.Delete(requestHash)
	return true
}

// handleQuorumTimeout waits for the quorum timeout and fails the batch if quorum wasn't reached.
// It exits early if doneCh is closed (indicating the batch was processed) or if the server is
// shutting down (context cancelled).
func (h *hostServer) handleQuorumTimeout(requestHash [32]byte, f uint32, doneCh <-chan struct{}) {
	var isShutdown bool
	select {
	case <-time.After(*quorumTimeout):
		// Timeout fired
	case <-doneCh:
		// Batch was processed, exit early
		return
	case <-h.ctx.Done():
		// Server is shutting down
		isShutdown = true
	}

	h.failBatchIfNotProcessed(requestHash, f, isShutdown)
}

func main() {
	flag.Parse()

	// Configure structured JSON logging via the shared chainlink-common logger.
	base, err := (&cllogger.Config{Level: zapcore.DebugLevel}).New()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	lggr := cllogger.Sugared(base).Named("host")

	// Validate that quorum timeout is less than cache TTL to prevent requests from hanging
	// if the cache entry expires before the timeout fires
	if *quorumTimeout >= cacheDefaultTTL {
		log.Fatalf("quorum-timeout (%v) must be less than cache TTL (%v)", *quorumTimeout, cacheDefaultTTL)
	}

	// Validate that the write timeout exceeds the quorum timeout so the server does
	// not sever a connection while handleExecute is still waiting for quorum.
	if *writeTimeout <= *quorumTimeout {
		log.Fatalf("write-timeout (%v) must be greater than quorum-timeout (%v)", *writeTimeout, *quorumTimeout)
	}

	if *requireBFTQuorum {
		lggr.Infow("BFT quorum required: batch threshold is 2f+1", "requireBFTQuorum", true)
	} else {
		lggr.Infow("standard quorum: batch threshold is f+1", "requireBFTQuorum", false)
	}

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Start servers. Optionally handle the config endpoint on a different port.
	host := NewHostServer(ctx, nil)
	host.logger = lggr
	mainMux := http.NewServeMux()

	var configServer *http.Server
	if *configHttpPort != *httpPort {
		configMux := http.NewServeMux()
		configMux.HandleFunc("POST "+types.SetConfigPath, host.handleSetConfig)
		configMux.HandleFunc("POST "+types.SettingsPath, host.handleInjectSettings)
		configServer = &http.Server{
			Addr:              fmt.Sprintf("127.0.0.1:%d", *configHttpPort),
			Handler:           configMux,
			ReadHeaderTimeout: *readHeaderTimeout,
			ReadTimeout:       *readTimeout,
			WriteTimeout:      *writeTimeout,
			IdleTimeout:       *idleTimeout,
			MaxHeaderBytes:    *maxHeaderBytes,
		}
		go func() {
			lggr.Infow("starting config server", "port", *configHttpPort)
			if err := configServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				lggr.Errorw("config server failed", "error", err)
			}
		}()
	} else {
		mainMux.HandleFunc("POST "+types.SetConfigPath, host.handleSetConfig)
		mainMux.HandleFunc("POST "+types.SettingsPath, host.handleInjectSettings)
	}

	mainMux.HandleFunc("PATCH "+types.SetConfigPath, host.handleUpdateConfig)
	mainMux.HandleFunc(types.PublicKeyPath, host.handleGetPublicKeys)
	mainMux.HandleFunc(types.ExecutePath, host.handleExecute)
	mainMux.HandleFunc("GET "+types.MemoryPath, host.handleMemory)

	mainServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", *httpPort),
		Handler:           mainMux,
		ReadHeaderTimeout: *readHeaderTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		IdleTimeout:       *idleTimeout,
		MaxHeaderBytes:    *maxHeaderBytes,
	}

	// Start main server in a goroutine
	go func() {
		lggr.Infow("starting main server", "port", *httpPort)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("main server failed", "error", err)
		}
	}()

	// Inject runtime config + settings into the enclave over vsock: the storage
	// endpoint + key (workflow-binary fetch) and the gateway URL (remote
	// dispatch). These can't be baked into the measured EIF, so the host supplies
	// them at runtime. The raw --settings JSON, when set, is forwarded verbatim
	// and overrides the individual flags; otherwise the payload is built from
	// them. Skipped only if nothing is configured.
	// TODO: re-inject on enclave restart.
	var payload []byte
	if *settingsJSON != "" {
		payload = []byte(*settingsJSON)
	} else {
		settings := types.WorkflowSettings{
			StorageKey:         *storageKey,
			StorageServiceURL:  *storageSvcURL,
			StorageServiceTLS:  *storageSvcTLS,
			GatewayURL:         *gatewayURL,
			MaxBinarySize:      *maxBinarySize,
			BinaryFetchTimeout: *binaryFetchTimeout,
			MaxCacheBytes:      *maxCacheBytes,
		}
		if settings.StorageKey != "" || settings.StorageServiceURL != "" || settings.GatewayURL != "" ||
			settings.MaxBinarySize != 0 || settings.BinaryFetchTimeout != 0 || settings.MaxCacheBytes != 0 {
			var err error
			if payload, err = json.Marshal(settings); err != nil {
				slog.Error("failed to marshal enclave settings", "error", err)
			}
		}
	}
	if len(payload) > 0 {
		go func() {
			if err := host.injectSettings(ctx, payload); err != nil {
				slog.Error("failed to inject settings into enclave", "error", err)
			}
		}()
	}

	// Wait for shutdown signal
	sig := <-sigCh
	lggr.Infow("received shutdown signal", "signal", sig.String())

	// Cancel context to stop all background goroutines (like quorum timeout handlers)
	cancel()

	// Give pending requests time to complete
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown servers gracefully
	if configServer != nil {
		if err := configServer.Shutdown(shutdownCtx); err != nil {
			lggr.Errorw("config server shutdown error", "error", err)
		}
	}
	if err := mainServer.Shutdown(shutdownCtx); err != nil {
		lggr.Errorw("main server shutdown error", "error", err)
	}

	lggr.Infow("graceful shutdown complete")
}
