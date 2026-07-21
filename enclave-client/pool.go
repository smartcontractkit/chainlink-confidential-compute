package enclaveclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	attestationvalidator "github.com/smartcontractkit/confidential-compute/enclave-client/attestation-validator"
	enclaveselector "github.com/smartcontractkit/confidential-compute/enclave-client/enclave-selector"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

// nopLogger discards all log output. Used when no logger is provided.
type nopLogger struct{}

func (nopLogger) Debugw(string, ...any) {}
func (nopLogger) Infow(string, ...any)  {}
func (nopLogger) Warnw(string, ...any)  {}
func (nopLogger) Errorw(string, ...any) {}

type CacheConfig struct {
	MaxTTL           time.Duration
	DefaultTTL       time.Duration
	CleanupInterval  time.Duration
	EnableCache      bool
	TTLBufferPercent float64
	// Proactive refresh settings
	EnableProactiveRefresh bool
	RefreshIntervalPercent float64 // Percentage of DefaultTTL to use as refresh interval (e.g., 0.6 = 60%)
	MinRefreshInterval     time.Duration
	RefreshTimeout         time.Duration
}

type SessionConfig struct {
	EnableSessionPersistence bool
	SessionHeaderName        string // Optional header to capture/send for session persistence (e.g., "Session-A")
}

var DefaultCacheConfig = CacheConfig{
	MaxTTL:                 30 * time.Minute,
	DefaultTTL:             types.DefaultPublicKeyCacheTTL,
	CleanupInterval:        10 * time.Minute,
	EnableCache:            types.DefaultEnablePublicKeyCache,
	TTLBufferPercent:       0.1,
	EnableProactiveRefresh: types.DefaultEnablePublicKeyCacheProactiveRefresh,
	RefreshIntervalPercent: types.DefaultRefreshIntervalPercent,
	MinRefreshInterval:     types.DefaultMinRefreshInterval,
	RefreshTimeout:         types.DefaultPublicKeyRequestTimeout,
}

var DefaultSessionConfig = SessionConfig{
	EnableSessionPersistence: true,
	SessionHeaderName:        types.StickySessionHeader,
}

type PoolConfig struct {
	Cache   CacheConfig
	Session SessionConfig
	// Metrics is an optional metrics emitter for the pool.
	// If nil, no metrics will be emitted.
	Metrics types.Emitter
	// Logger is an optional structured logger.
	// If nil, logging is disabled.
	Logger types.Logger

	// RequestTimeoutResolverFn resolves per-call timeouts dynamically.
	// publicKey is true for GetPublicKeys and false otherwise.
	// It is invoked on each enclave-client operation
	RequestTimeoutResolverFn func(ctx context.Context, publicKey bool) (time.Duration, error)
}

type scopedEmitter struct {
	base     types.Emitter
	defaults map[string]any
}

func newScopedEmitter(base types.Emitter, defaults map[string]any) *scopedEmitter {
	return &scopedEmitter{base: base, defaults: defaults}
}

func (s *scopedEmitter) Emit(event string, details map[string]any) {
	merged := make(map[string]any, len(s.defaults)+len(details))
	for k, v := range s.defaults {
		merged[k] = v
	}
	for k, v := range details {
		merged[k] = v
	}
	s.base.Emit(event, merged)
}

type SessionData struct {
	Headers http.Header
}

type cachedPublicKeyData struct {
	Data         types.EnclavePublicKeyData `json:"data"`
	OriginalTTLs []time.Duration            `json:"original_ttls"`
	CachedAt     time.Time                  `json:"cached_at"`
}

// enclavePool is the default implementation of EnclaveClient.
// It uses an injected EnclaveSelector to choose enclaves for a given request
// and validates attestation reports from enclaves.
type enclavePool struct {
	nodes           []types.Enclave
	nodesLock       sync.RWMutex
	httpClient      *http.Client
	enclaveSelector enclaveselector.EnclaveSelector
	publicKeyCache  *util.Cache[cachedPublicKeyData]
	cacheConfig     CacheConfig
	// Proactive refresh fields
	refreshStopCh chan struct{}
	refreshWg     sync.WaitGroup
	refreshCtx    context.Context
	refreshCancel context.CancelFunc
	lastRefresh   map[[32]byte]time.Time
	lastRefreshMu sync.RWMutex

	// Session persistence fields
	sessionConfig SessionConfig
	sessionStore  map[string]*SessionData
	sessionLock   sync.RWMutex

	// Metrics emitter (optional)
	metrics types.Emitter

	// Structured logger
	lggr types.Logger

	requestTimeoutResolverFn func(ctx context.Context, publicKey bool) (time.Duration, error)
}

var _ EnclaveClient = (*enclavePool)(nil)

// NewPool creates an enclave pool with default cache/session and request timeouts.
func NewPool(
	nodes []types.Enclave,
	selector enclaveselector.EnclaveSelector,
	httpClient *http.Client,
) (EnclaveClient, error) {
	return NewPoolWithConfig(nodes, selector, httpClient, PoolConfig{
		Cache:   DefaultCacheConfig,
		Session: DefaultSessionConfig,
	})
}

func NewPoolWithConfig(
	nodes []types.Enclave,
	selector enclaveselector.EnclaveSelector,
	httpClient *http.Client,
	config PoolConfig,
) (*enclavePool, error) {
	if selector == nil {
		selector = enclaveselector.NewRoundRobinEnclaveSelector()
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if config.RequestTimeoutResolverFn == nil {
		return nil, fmt.Errorf("enclave request timeout resolver function is required")
	}
	pool := &enclavePool{
		nodes:                    nodes,
		httpClient:               httpClient,
		enclaveSelector:          selector,
		cacheConfig:              config.Cache,
		sessionConfig:            config.Session,
		sessionStore:             make(map[string]*SessionData),
		metrics:                  config.Metrics,
		lggr:                     config.Logger,
		requestTimeoutResolverFn: config.RequestTimeoutResolverFn,
	}

	if pool.lggr == nil {
		pool.lggr = nopLogger{}
	}

	pool.lggr.Infow("enclave pool created", "nodeCount", len(nodes), "cacheEnabled", config.Cache.EnableCache, "proactiveRefresh", config.Cache.EnableProactiveRefresh, "sessionPersistence", config.Session.EnableSessionPersistence)

	if config.Cache.EnableCache {
		pool.publicKeyCache = util.NewCache[cachedPublicKeyData](&config.Cache.DefaultTTL, &config.Cache.CleanupInterval)

		// If enabled, rehydrate the cache with enclave public keys at a regular frequency.
		if config.Cache.EnableProactiveRefresh {
			pool.refreshStopCh = make(chan struct{})
			pool.lastRefresh = make(map[[32]byte]time.Time)
			pool.refreshCtx, pool.refreshCancel = context.WithCancel(context.Background())

			pool.initialWarmup(pool.refreshCtx)

			pool.refreshWg.Add(1)
			go pool.refreshCacheLoop(pool.refreshCtx)
		}
	}

	return pool, nil
}

func (c *enclavePool) resolveRequestTimeout(ctx context.Context, publicKey bool) (time.Duration, error) {
	return c.requestTimeoutResolverFn(ctx, publicKey)

}

// GetPublicKeys fetches a list of enclaves and their current public key data to be used for a provided request ID & enclave specifications.
func (c *enclavePool) GetPublicKeys(ctx context.Context, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.EnclavePublicKeyData, error) {
	// Read c.nodes directly. The round-robin selector picks by
	// nodes[bigInt(requestID) % len(nodes)] and all DON nodes must converge
	// on the same enclave for the same requestID so F+1 attested responses
	// agree. Sourcing from a map randomizes order per call and breaks that
	// convergence across DON nodes.
	c.nodesLock.RLock()
	nodes := append([]types.Enclave{}, c.nodes...)
	c.nodesLock.RUnlock()

	reqIDHex := hex.EncodeToString(requestID[:])
	c.lggr.Debugw("selecting enclaves for public key fetch", "reqID", reqIDHex, "nodeCount", len(nodes))

	enclaves, err := c.enclaveSelector.SelectEnclaves(nodes, requestID, checkRequirements)
	if err != nil {
		c.lggr.Warnw("enclave selection failed", "reqID", reqIDHex, "error", err)
		return nil, err
	}
	c.lggr.Debugw("enclaves selected", "reqID", reqIDHex, "selectedCount", len(enclaves))

	var (
		responsesMu sync.Mutex
		responses   []types.EnclavePublicKeyData
	)

	// Apply a shorter timeout specifically for public key fetches so that
	// requests to dead enclaves fail fast rather than blocking for the full
	// httpClient timeout (e.g. 5s).
	pkTimeout, err := c.resolveRequestTimeout(ctx, true)
	if err != nil {
		return nil, err
	}
	pkCtx, pkCancel := context.WithTimeout(ctx, pkTimeout)
	defer pkCancel()

	g, gCtx := errgroup.WithContext(pkCtx)

	for _, enclave := range enclaves {
		enclave := enclave
		g.Go(func() error {
			enclaveIDHex := hex.EncodeToString(enclave.EnclaveID[:])
			// Network-first strategy: always attempt a fresh fetch.
			// Fall back to a cached key only on failure.
			publicKeyData, err := c.getSingleEnclavePublicKey(gCtx, enclave, requestID)
			if err != nil {
				if cached := c.getCachedPublicKey(enclave.EnclaveID); cached != nil {
					c.lggr.Debugw("public key cache fallback hit", "reqID", reqIDHex, "enclaveID", enclaveIDHex)
					responsesMu.Lock()
					responses = append(responses, *cached)
					responsesMu.Unlock()
					return nil
				}
				return err
			}

			// Cache the fetched public key data
			c.setCachedPublicKey(enclave.EnclaveID, *publicKeyData)

			responsesMu.Lock()
			responses = append(responses, *publicKeyData)
			responsesMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return responses, nil
}

func (c *enclavePool) ExecuteBatch(ctx context.Context, reqs []types.SignedComputeRequest, eIDs [][32]byte) ([]types.ExecuteResponse, error) {
	c.lggr.Debugw("executing batch", "requestCount", len(reqs), "enclaveCount", len(eIDs))
	timeout, err := c.resolveRequestTimeout(ctx, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c.nodesLock.RLock()
	var enclaves []types.Enclave
	for _, enclaveID := range eIDs {
		var found bool
		for _, node := range c.nodes {
			if node.EnclaveID == enclaveID {
				enclaves = append(enclaves, node)
				found = true
				break
			}
		}
		if !found {
			c.nodesLock.RUnlock()
			return nil, fmt.Errorf("enclaveID %x not found in pool", enclaveID)
		}
	}
	c.nodesLock.RUnlock()

	var (
		responsesMu sync.Mutex
		responses   = make([]types.ExecuteResponse, len(enclaves))
	)
	g, ctx := errgroup.WithContext(ctx)

	for i, enclave := range enclaves {
		i, enclave, req := i, enclave, reqs[i]
		g.Go(func() error {
			enclaveIDHex := hex.EncodeToString(enclave.EnclaveID[:])
			endpoint := enclave.EnclaveURL + types.ExecutePath
			body, err := json.Marshal(req)
			if err != nil {
				return err
			}
			httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
			if err != nil {
				return err
			}
			httpReq.Header.Set("Content-Type", "application/json")
			err = util.SetAuthHeader(enclave, httpReq)
			if err != nil {
				return fmt.Errorf("could not set auth header for enclave %s %w", enclave.EnclaveID, err)
			}

			c.applySession(req.EnclaveEphemeralPublicKey, httpReq)

			resp, err := c.httpClient.Do(httpReq)
			if err != nil {
				return err
			}
			defer util.SafeClose(resp)
			respBody, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
			if err != nil {
				return err
			}
			if int64(len(respBody)) > types.MaxEnclaveResponseBodyBytes {
				return fmt.Errorf("enclave response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
			}
			if resp.StatusCode != http.StatusOK {
				c.lggr.Warnw("enclave returned non-OK status",
					"enclaveID", enclaveIDHex,
					"status", resp.StatusCode,
					"responseLen", len(respBody))
				// Try to extract and forward enclave metrics from JSON error responses.
				// The enclave may return metrics (e.g. attestation_creation_failed) even on failure.
				if c.metrics != nil {
					enclaveMetrics := newScopedEmitter(c.metrics, map[string]any{
						"component": "enclave",
					})
					var errResp types.EnclaveErrorResponse
					if json.Unmarshal(respBody, &errResp) == nil {
						// Prefer the ordered list (dup-preserving); fall back to the map.
						if len(errResp.MetricEvents) > 0 {
							for _, ev := range errResp.MetricEvents {
								enclaveMetrics.Emit(ev.Event, ev.Details)
							}
						} else {
							for eventName, details := range errResp.Metrics {
								if detailsMap, ok := details.(map[string]any); ok {
									enclaveMetrics.Emit(eventName, detailsMap)
								}
							}
						}
						if errResp.Error != "" {
							return fmt.Errorf("execute failed: %s", errResp.Error)
						}
					}
				}
				return fmt.Errorf("execute failed: %s", string(respBody))
			}
			var out types.ExecuteResponse
			if err := json.Unmarshal(respBody, &out); err != nil {
				return err
			}
			if err := c.validateAttestation(enclave, out.UserDataHash(req.Version), out.Attestation); err != nil {
				c.lggr.Errorw("attestation validation failed",
					"enclaveID", enclaveIDHex,
					"endpoint", "execute",
					"error", err)
				if c.metrics != nil {
					c.metrics.Emit("attestation_validation_failed", map[string]any{
						"enclave.id": util.EncodeToString(enclave.EnclaveID[:]),
						"endpoint":   "execute",
						"error":      err.Error(),
					})
				}
				return fmt.Errorf("attestation validation failed for ExecuteBatch: %w", err)
			}
			if out.RequestHash != req.Hash() {
				return fmt.Errorf("mismatched request hash in response from enclave %x: got %x, want %x", enclave.EnclaveID, out.RequestHash, req.Hash())
			}
			if req.Version != types.ServiceConfidentialComputeVersionLegacy && out.ApplicationRequestID != req.ApplicationRequestID {
				return fmt.Errorf("mismatched application request ID in response from enclave %x: got %q, want %q", enclave.EnclaveID, out.ApplicationRequestID, req.ApplicationRequestID)
			}
			responsesMu.Lock()
			responses[i] = out
			responsesMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return responses, nil
}

// UpdateConfig broadcasts a signed config-update vote to every enclave in the pool.
// Best-effort: per-node failures are joined into the returned error.
func (c *enclavePool) UpdateConfig(ctx context.Context, update types.UpdateConfigRequest) error {
	timeout, err := c.resolveRequestTimeout(ctx, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c.nodesLock.RLock()
	nodes := append([]types.Enclave{}, c.nodes...)
	c.nodesLock.RUnlock()

	if len(nodes) == 0 {
		return errors.New("no enclaves in pool to update config")
	}

	body, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal config update: %w", err)
	}

	var (
		errsMu sync.Mutex
		errs   error
		g      errgroup.Group
	)

	for _, enclave := range nodes {
		enclave := enclave
		g.Go(func() error {
			if err := c.updateSingleEnclaveConfig(ctx, enclave, body); err != nil {
				errsMu.Lock()
				errs = errors.Join(errs, err)
				errsMu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	return errs
}

// GetConfigs returns each enclave's current config, ordered the same as the pool's
// node list. Configs are read from /publicKeys and attestation-validated.
func (c *enclavePool) GetConfigs(ctx context.Context) ([]types.EnclaveConfig, error) {
	timeout, err := c.resolveRequestTimeout(ctx, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c.nodesLock.RLock()
	nodes := append([]types.Enclave{}, c.nodes...)
	c.nodesLock.RUnlock()

	if len(nodes) == 0 {
		return nil, errors.New("no enclaves in pool to read config")
	}

	configs := make([]types.EnclaveConfig, len(nodes))
	var (
		errsMu sync.Mutex
		errs   error
		g      errgroup.Group
	)

	for i, enclave := range nodes {
		i, enclave := i, enclave
		g.Go(func() error {
			pk, err := c.getSingleEnclavePublicKey(ctx, enclave, [32]byte{})
			if err != nil {
				errsMu.Lock()
				errs = errors.Join(errs, err)
				errsMu.Unlock()
				return nil
			}
			configs[i] = pk.Config
			return nil
		})
	}
	_ = g.Wait()
	if errs != nil {
		return nil, errs
	}
	return configs, nil
}

func (c *enclavePool) updateSingleEnclaveConfig(ctx context.Context, enclave types.Enclave, body []byte) error {
	enclaveIDHex := hex.EncodeToString(enclave.EnclaveID[:])
	endpoint := enclave.EnclaveURL + types.SetConfigPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := util.SetAuthHeader(enclave, httpReq); err != nil {
		return fmt.Errorf("could not set auth header for enclave %s %w", enclave.EnclaveID, err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer util.SafeClose(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(respBody)) > types.MaxEnclaveResponseBodyBytes {
		return fmt.Errorf("config update response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
	}

	// 202 Accepted means the vote was recorded but quorum has not yet been reached.
	if resp.StatusCode == http.StatusAccepted {
		c.lggr.Debugw("config update vote accepted, awaiting quorum", "enclaveID", enclaveIDHex)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config update failed for enclave %x: %s", enclave.EnclaveID, string(respBody))
	}

	var out types.UpdateConfigResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return err
	}
	if !out.Applied {
		c.lggr.Debugw("config update vote recorded", "enclaveID", enclaveIDHex,
			"signersCollected", out.SignersCollected, "signersRequired", out.SignersRequired)
		return nil
	}

	// Quorum reached: validate the attestation over the applied config.
	setConfigResp := types.SetConfigResponse{Config: out.Config}
	if err := c.validateAttestation(enclave, setConfigResp.UserDataHash(), out.Attestation); err != nil {
		c.lggr.Errorw("config update attestation validation failed", "enclaveID", enclaveIDHex, "error", err)
		return fmt.Errorf("config update attestation validation failed for enclave %x: %w", enclave.EnclaveID, err)
	}
	c.lggr.Infow("config update applied by enclave", "enclaveID", enclaveIDHex,
		"signersCollected", out.SignersCollected, "signersRequired", out.SignersRequired)
	return nil
}

// UpdateNodes validates each new node by fetching and attestation-checking its
// public keys before committing them to the pool. A failure means the node is
// unreachable or its attestation measurements are misconfigured; in that case
// the existing nodes are retained and the error is returned so the caller can
// alert and fall back.
func (c *enclavePool) UpdateNodes(ctx context.Context, nodes []types.Enclave) error {
	c.nodesLock.RLock()
	unchanged := (&types.EnclavesList{Enclaves: nodes}).Hash() == (&types.EnclavesList{Enclaves: c.nodes}).Hash()
	c.nodesLock.RUnlock()
	if unchanged {
		return nil
	}

	if err := c.validateNodes(ctx, nodes); err != nil {
		return err
	}

	c.nodesLock.Lock()
	defer c.nodesLock.Unlock()

	c.lggr.Infow("updating enclave nodes", "oldCount", len(c.nodes), "newCount", len(nodes))
	c.nodes = nodes

	if c.cacheConfig.EnableCache && c.publicKeyCache != nil {
		c.publicKeyCache.Flush()
		if c.cacheConfig.EnableProactiveRefresh {
			c.lastRefreshMu.Lock()
			c.lastRefresh = make(map[[32]byte]time.Time)
			c.lastRefreshMu.Unlock()

			ctx := c.refreshCtx
			if ctx == nil {
				ctx = context.Background()
			}
			c.refreshWg.Add(1)
			go func() {
				defer c.refreshWg.Done()
				c.refreshAllCachedKeys(ctx)
			}()
		}
	}
	return nil
}

// validateNodes fetches public keys from every node concurrently, attestation-
// validating each response. It returns the first error encountered, leaving the
// pool's node list untouched.
func (c *enclavePool) validateNodes(ctx context.Context, nodes []types.Enclave) error {
	timeout, err := c.resolveRequestTimeout(ctx, true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	g, gCtx := errgroup.WithContext(ctx)
	for _, enclave := range nodes {
		enclave := enclave
		g.Go(func() error {
			if _, err := c.getSingleEnclavePublicKey(gCtx, enclave, [32]byte{}); err != nil {
				return fmt.Errorf("public key fetch failed for enclave %x: %w", enclave.EnclaveID, err)
			}
			return nil
		})
	}
	return g.Wait()
}

func (c *enclavePool) getCachedPublicKey(enclaveID [32]byte) *types.EnclavePublicKeyData {
	if !c.cacheConfig.EnableCache || c.publicKeyCache == nil {
		return nil
	}

	if item, found := c.publicKeyCache.Get(enclaveID); found {
		return &item.Data
	}

	return nil
}

func (c *enclavePool) setCachedPublicKey(enclaveID [32]byte, data types.EnclavePublicKeyData) {
	if !c.cacheConfig.EnableCache || c.publicKeyCache == nil {
		return
	}

	effectiveTTL := c.calculateEffectiveTTL(data.TTLs)

	if effectiveTTL <= 0 {
		return
	}

	cached := cachedPublicKeyData{
		Data:         data,
		OriginalTTLs: data.TTLs,
		CachedAt:     time.Now(),
	}

	c.publicKeyCache.Set(enclaveID, cached, &effectiveTTL)
}

func (c *enclavePool) calculateEffectiveTTL(enclaveTTLs []time.Duration) time.Duration {
	var minTTL time.Duration

	if len(enclaveTTLs) > 0 {
		minTTL = enclaveTTLs[0]
		for _, ttl := range enclaveTTLs[1:] {
			if ttl < minTTL {
				minTTL = ttl
			}
		}

		if minTTL > c.cacheConfig.MaxTTL {
			minTTL = c.cacheConfig.MaxTTL
		}
	} else {
		minTTL = c.cacheConfig.DefaultTTL
	}

	bufferTime := time.Duration(float64(minTTL) * c.cacheConfig.TTLBufferPercent)
	if bufferTime < time.Second {
		bufferTime = time.Second
	}

	return minTTL - bufferTime
}

func (c *enclavePool) initialWarmup(ctx context.Context) {
	c.refreshAllCachedKeys(ctx)
}

func (c *enclavePool) refreshCacheLoop(ctx context.Context) {
	defer c.refreshWg.Done()

	refreshInterval := time.Duration(float64(c.cacheConfig.DefaultTTL) * c.cacheConfig.RefreshIntervalPercent)
	if refreshInterval < c.cacheConfig.MinRefreshInterval {
		refreshInterval = c.cacheConfig.MinRefreshInterval
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.refreshStopCh:
			return
		case <-ticker.C:
			c.refreshAllCachedKeys(ctx)
		}
	}
}

func (c *enclavePool) refreshAllCachedKeys(ctx context.Context) {
	c.nodesLock.RLock()
	nodes := append([]types.Enclave{}, c.nodes...)
	c.nodesLock.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, c.cacheConfig.RefreshTimeout)
	defer cancel()

	// This refresh pass is best effort. Do not use errgroup.WithContext here,
	// or one timed-out/failed refresh will short-circuit the rest of the loop
	// before the shared refresh timeout has elapsed.
	var g errgroup.Group

	for _, node := range nodes {
		node := node
		g.Go(func() error {
			return c.refreshSingleKey(ctx, node)
		})
	}

	// Best effort - don't block on errors
	_ = g.Wait()
}

func (c *enclavePool) refreshSingleKey(ctx context.Context, enclave types.Enclave) error {
	// Use zero requestID for background refresh since it's only used for node selection here, and not downstream
	dummyRequestID := [32]byte{}

	enclaveIDHex := hex.EncodeToString(enclave.EnclaveID[:])
	publicKeyData, err := c.getSingleEnclavePublicKey(ctx, enclave, dummyRequestID)
	if err != nil {
		c.enclaveSelector.SetEnclaveLiveness(enclave.EnclaveID, false)
		c.lggr.Warnw("cache refresh failed", "enclaveID", enclaveIDHex, "error", err)
		if c.metrics != nil {
			c.metrics.Emit("cache_refresh_failed", map[string]any{
				"enclave.id": util.EncodeToString(enclave.EnclaveID[:]),
				"error":      err.Error(),
			})
		}
		return err
	}

	c.setCachedPublicKey(enclave.EnclaveID, *publicKeyData)
	c.enclaveSelector.SetEnclaveLiveness(enclave.EnclaveID, true)
	c.lggr.Debugw("cache refresh succeeded", "enclaveID", enclaveIDHex)

	c.lastRefreshMu.Lock()
	c.lastRefresh[enclave.EnclaveID] = time.Now()
	c.lastRefreshMu.Unlock()

	return nil
}

func (c *enclavePool) getSingleEnclavePublicKey(ctx context.Context, enclave types.Enclave, requestID [32]byte) (*types.EnclavePublicKeyData, error) {
	enclaveIDHex := hex.EncodeToString(enclave.EnclaveID[:])
	endpoint := enclave.EnclaveURL + types.PublicKeyPath
	params := urlpkg.Values{}
	if requestID != ([32]byte{}) {
		params.Set("requestID", hex.EncodeToString(requestID[:]))
	}
	urlWithParams := endpoint + "?" + params.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, "GET", urlWithParams, nil)
	if err != nil {
		return nil, err
	}
	err = util.SetAuthHeader(enclave, httpReq)
	if err != nil {
		return nil, fmt.Errorf("could not set auth header for enclave %s %w", enclave.EnclaveID, err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer util.SafeClose(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(respBody)) > types.MaxEnclaveResponseBodyBytes {
		return nil, fmt.Errorf("publicKeys response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
	}

	if resp.StatusCode != http.StatusOK {
		c.lggr.Warnw("public key request failed",
			"enclaveID", enclaveIDHex,
			"status", resp.StatusCode,
			"responseLen", len(respBody))
		return nil, fmt.Errorf("request failed for enclave %x: %s", enclave.EnclaveID, string(respBody))
	}

	var out types.PublicKeyResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}

	if out.Config.IsZero() {
		return nil, fmt.Errorf("enclave %x returned unconfigured public keys (t=%d f=%d)", enclave.EnclaveID, out.Config.T, out.Config.F)
	}

	c.updateSession(out.PublicKeys, resp)

	publicKeyHash := out.PublicKeyHash()
	if err := c.validateAttestation(enclave, publicKeyHash[:], out.Attestation); err != nil {
		c.lggr.Errorw("attestation validation failed",
			"enclaveID", enclaveIDHex,
			"endpoint", "publicKeys",
			"error", err)
		if c.metrics != nil {
			c.metrics.Emit("attestation_validation_failed", map[string]any{
				"enclave.id": util.EncodeToString(enclave.EnclaveID[:]),
				"endpoint":   "publicKeys",
				"error":      err.Error(),
			})
		}
		return nil, fmt.Errorf("attestation validation failed for getSingleEnclavePublicKey: %w", err)
	}

	c.lggr.Debugw("public key fetched",
		"enclaveID", enclaveIDHex,
		"pubKeyCount", len(out.PublicKeys),
		"ttlCount", len(out.TTLs))

	publicKeyData := types.EnclavePublicKeyData{
		PublicKeyResponse: out,
		EnclaveID:         enclave.EnclaveID,
	}
	return &publicKeyData, nil
}

func (c *enclavePool) Close() error {
	c.nodesLock.Lock()
	if c.refreshStopCh != nil {
		close(c.refreshStopCh)
		c.refreshStopCh = nil // Prevent double-close
		if c.refreshCancel != nil {
			c.refreshCancel()
		}
		c.nodesLock.Unlock()
		c.refreshWg.Wait()
		return nil
	}
	c.nodesLock.Unlock()
	return nil
}

func (c *enclavePool) GetCacheStats() map[string]interface{} {
	if !c.cacheConfig.EnableCache || c.publicKeyCache == nil {
		return map[string]interface{}{"cache_enabled": false}
	}

	stats := map[string]interface{}{
		"cache_enabled":       true,
		"item_count":          c.publicKeyCache.Size(),
		"max_ttl_seconds":     c.cacheConfig.MaxTTL.Seconds(),
		"default_ttl_seconds": c.cacheConfig.DefaultTTL.Seconds(),
		"ttl_buffer_percent":  c.cacheConfig.TTLBufferPercent,
	}

	if c.cacheConfig.EnableProactiveRefresh {
		c.lastRefreshMu.RLock()
		freshCount := 0
		staleCount := 0
		cutoff := time.Now().Add(-c.cacheConfig.DefaultTTL)
		for _, t := range c.lastRefresh {
			if t.After(cutoff) {
				freshCount++
			} else {
				staleCount++
			}
		}
		c.lastRefreshMu.RUnlock()

		stats["proactive_refresh_enabled"] = true
		stats["fresh_enclaves"] = freshCount
		stats["stale_enclaves"] = staleCount
		stats["refresh_interval_seconds"] = time.Duration(float64(c.cacheConfig.DefaultTTL) * c.cacheConfig.RefreshIntervalPercent).Seconds()
	} else {
		stats["proactive_refresh_enabled"] = false
	}

	return stats
}

func (c *enclavePool) updateSession(keys [][]byte, resp *http.Response) {
	if !c.sessionConfig.EnableSessionPersistence {
		return
	}

	var headerValue string
	if c.sessionConfig.SessionHeaderName != "" {
		headerValue = resp.Header.Get(c.sessionConfig.SessionHeaderName)
	}

	if headerValue == "" {
		return
	}

	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		keyStr := util.EncodeToString(key)
		currentSession, ok := c.sessionStore[keyStr]
		if !ok {
			currentSession = &SessionData{
				Headers: make(http.Header),
			}
			c.sessionStore[keyStr] = currentSession
		}

		if headerValue != "" {
			if currentSession.Headers == nil {
				currentSession.Headers = make(http.Header)
			}
			currentSession.Headers.Set(c.sessionConfig.SessionHeaderName, headerValue)
		}
	}
}

func (c *enclavePool) applySession(key []byte, req *http.Request) bool {
	if !c.sessionConfig.EnableSessionPersistence {
		return false
	}

	c.sessionLock.RLock()
	session, ok := c.sessionStore[util.EncodeToString(key)]
	c.sessionLock.RUnlock()

	if !ok || session == nil {
		return false
	}

	for k, v := range session.Headers {
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}

	return true
}

func (c *enclavePool) validateAttestation(enclave types.Enclave, userData []byte, attestation []byte) error {
	if validated, validationErr := validateAttestationAgainstEnclaves([]types.Enclave{enclave}, attestation, userData, c.lggr); validated {
		return nil
	} else {
		if validationErr == nil {
			validationErr = errors.New("no trusted measurements configured")
		}
		return fmt.Errorf("attestation validation failed for enclave %x (received %s): %w",
			enclave.EnclaveID, attestationvalidator.DescribeMeasurements(attestation), validationErr)
	}
}

// validateAttestationAgainstEnclaves tries to validate the attestation against
// each candidate enclave's trusted measurements, selecting the validator by the
// candidate's enclave type. It returns true on the first measurement that
// validates, or the joined errors from every attempt otherwise.
func validateAttestationAgainstEnclaves(enclaves []types.Enclave, attestation []byte, userData []byte, lggr types.Logger) (bool, error) {
	var validationErr error
	for _, enclave := range enclaves {
		validator := attestationvalidator.ForEnclaveType(enclave.EnclaveType, lggr)
		for _, measurements := range enclave.TrustedValues {
			if err := validator.ValidateAttestation(attestation, userData, measurements); err != nil {
				validationErr = errors.Join(validationErr, err)
				continue
			}
			return true, nil
		}
	}
	return false, validationErr
}
