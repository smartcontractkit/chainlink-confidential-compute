package enclaveclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enclaveclient "github.com/smartcontractkit/confidential-compute/enclave-client"
	enclaveselector "github.com/smartcontractkit/confidential-compute/enclave-client/enclave-selector"
	testdata "github.com/smartcontractkit/confidential-compute/enclave-client/test-data"
	"github.com/smartcontractkit/confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures and helpers

type testFixture struct {
	RequestID           [32]byte
	EnclaveID1          [32]byte
	EnclaveID2          [32]byte
	EphemeralPublicKey  []byte
	Attestation         []byte
	PublicData          []byte
	TrustedMeasurements []byte
}

func newTestFixture(t *testing.T) *testFixture {
	emptyPCR, _ := hex.DecodeString(testdata.EmptyPCR)
	trustedMeasurements := nitro.PCRs{
		PCR0: emptyPCR,
		PCR1: emptyPCR,
		PCR2: emptyPCR,
	}
	trustedMeasurementsBin, err := json.Marshal(trustedMeasurements)
	require.NoError(t, err)

	return &testFixture{
		RequestID:           sha256.Sum256([]byte("test-request-id")),
		EnclaveID1:          sha256.Sum256([]byte("test-enclave-id-1")),
		EnclaveID2:          sha256.Sum256([]byte("test-enclave-id-2")),
		EphemeralPublicKey:  []byte("0x123456"),
		Attestation:         []byte(types.FakeAttestationDocument),
		PublicData:          []byte("test-output"),
		TrustedMeasurements: trustedMeasurementsBin,
	}
}

func (f *testFixture) createNode(serverURL string, enclaveID [32]byte) types.Enclave {
	return types.Enclave{
		EnclaveID:     enclaveID,
		EnclaveURL:    serverURL,
		EnclaveType:   types.EnclaveTypeFake,
		TrustedValues: [][]byte{[]byte("foobar"), f.TrustedMeasurements},
	}
}

func (f *testFixture) createNodes(serverURL string, count int) []types.Enclave {
	nodes := make([]types.Enclave, count)
	for i := 0; i < count; i++ {
		enclaveID := f.EnclaveID1
		if i == 1 {
			enclaveID = f.EnclaveID2
		}
		nodes[i] = f.createNode(serverURL, enclaveID)
	}
	return nodes
}

func (f *testFixture) createPublicKeyResponse(ttls ...time.Duration) types.PublicKeyResponse {
	defaultTTLs := []time.Duration{5 * time.Minute}
	if len(ttls) > 0 {
		defaultTTLs = ttls
	}

	return types.PublicKeyResponse{
		PublicKeys:    [][]byte{f.EphemeralPublicKey},
		CreationTimes: []time.Time{time.Now()},
		TTLs:          defaultTTLs,
		Config:        testEnclaveConfig(),
		Attestation:   f.Attestation,
	}
}

// testEnclaveConfig returns a minimal non-zero config so fetched public keys
// are not rejected as unconfigured by the pool.
func testEnclaveConfig() types.EnclaveConfig {
	return types.EnclaveConfig{
		Signers:         [][]byte{[]byte("signer")},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               1,
	}
}

func createMockServer(t *testing.T, fixture *testFixture, requestCount *int32, ttls ...time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount != nil {
			atomic.AddInt32(requestCount, 1)
		}

		resp := fixture.createPublicKeyResponse(ttls...)
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
}

// Mock implementations

type mockAllEnclaveSelector struct{}

func (s *mockAllEnclaveSelector) SelectEnclaves(nodes []types.Enclave, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.Enclave, error) {
	return nodes, nil
}

func (s *mockAllEnclaveSelector) SetEnclaveLiveness(enclaveID [32]byte, isAlive bool) {}

type mockSingleEnclaveSelector struct{}

func (s *mockSingleEnclaveSelector) SelectEnclaves(nodes []types.Enclave, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.Enclave, error) {
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes[:1], nil
}

func (s *mockSingleEnclaveSelector) SetEnclaveLiveness(enclaveID [32]byte, isAlive bool) {}

// Cache config helpers

func defaultCacheConfig() enclaveclient.CacheConfig {
	return enclaveclient.CacheConfig{
		EnableCache:      true,
		MaxTTL:           30 * time.Minute,
		DefaultTTL:       5 * time.Minute,
		CleanupInterval:  10 * time.Minute,
		TTLBufferPercent: 0.1,
	}
}

func proactiveCacheConfig(ttl time.Duration, refreshPercent float64) enclaveclient.CacheConfig {
	config := defaultCacheConfig()
	config.EnableProactiveRefresh = true
	config.DefaultTTL = ttl
	config.RefreshIntervalPercent = refreshPercent
	config.MinRefreshInterval = 30 * time.Second
	config.RefreshTimeout = 5 * time.Second
	if ttl < 1*time.Second {
		config.MinRefreshInterval = 50 * time.Millisecond
	}
	return config
}

func defaultRequestTimeoutResolver() func(context.Context, bool) (time.Duration, error) {
	return func(_ context.Context, publicKey bool) (time.Duration, error) {
		if publicKey {
			return types.DefaultPublicKeyRequestTimeout, nil
		}
		return types.DefaultEnclaveRequestTimeout, nil
	}
}

func staticRequestTimeoutResolver(timeout time.Duration) func(context.Context, bool) (time.Duration, error) {
	return func(_ context.Context, _ bool) (time.Duration, error) {
		return timeout, nil
	}
}

// newTestPool / newTestPoolWithCache build a pool with default request timeouts.
func newTestPoolWithCache(nodes []types.Enclave, selector enclaveselector.EnclaveSelector, httpClient *http.Client, cacheConfig enclaveclient.CacheConfig) (enclaveclient.EnclaveClient, error) {
	return enclaveclient.NewPoolWithConfig(nodes, selector, httpClient, enclaveclient.PoolConfig{
		Cache:                    cacheConfig,
		Session:                  enclaveclient.DefaultSessionConfig,
		RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
	})
}

func newTestPool(nodes []types.Enclave, selector enclaveselector.EnclaveSelector, httpClient *http.Client) (enclaveclient.EnclaveClient, error) {
	return newTestPoolWithCache(nodes, selector, httpClient, enclaveclient.DefaultCacheConfig)
}

// Tests

func TestNewPool(t *testing.T) {
	t.Parallel()
	nodes := []types.Enclave{{EnclaveURL: "http://localhost:8080", EnclaveType: "type1"}}
	pool, err := newTestPool(nodes, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestGetPublicKeysConcurrent(t *testing.T) {
	t.Parallel()

	testRequestID := sha256.Sum256([]byte("test-request-id"))
	testEphemeralPublicKey := []byte("0x123456")
	testAttestation := []byte(types.FakeAttestationDocument)
	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:  [][]byte{testEphemeralPublicKey},
		Config:      testEnclaveConfig(),
		Attestation: testAttestation,
	}

	var (
		arrived sync.WaitGroup
		release = make(chan struct{})
	)

	arrived.Add(2)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("requestID"))

		arrived.Done()
		<-release

		resp := &testPublicKeyResponse
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	fixture := newTestFixture(t)

	config := defaultCacheConfig()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 2),
		&mockAllEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    config,
			Session:                  enclaveclient.DefaultSessionConfig,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		resp, err := pool.GetPublicKeys(context.Background(), testRequestID, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 2, len(resp))
		for i := range resp {
			assert.Equal(t, 1, len(resp[i].PublicKeys))
			assert.Equal(t, testEphemeralPublicKey, resp[i].PublicKeys[0])
			assert.Equal(t, testAttestation, resp[i].Attestation)
		}
		done <- struct{}{}
	}()

	waitCh := make(chan struct{})
	go func() {
		arrived.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for both handlers to arrive (concurrency likely broken)")
	}

	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for GetPublicKeys to finish")
	}
}

func TestGetConfigs(t *testing.T) {
	t.Parallel()

	fixture := newTestFixture(t)

	configA := types.EnclaveConfig{
		Signers:         [][]byte{[]byte("signer-a1"), []byte("signer-a2")},
		MasterPublicKey: []byte("mpk"),
		T:               3,
		F:               1,
	}
	configB := types.EnclaveConfig{
		Signers:         [][]byte{[]byte("signer-b1")},
		MasterPublicKey: []byte("mpk"),
		T:               3,
		F:               1,
	}

	newConfigServer := func(cfg types.EnclaveConfig) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/publicKeys", r.URL.Path)
			resp := types.PublicKeyResponse{
				PublicKeys:  [][]byte{fixture.EphemeralPublicKey},
				Attestation: fixture.Attestation,
				Config:      cfg,
			}
			require.NoError(t, json.NewEncoder(w).Encode(&resp))
		}))
	}

	newPool := func(t *testing.T, nodes []types.Enclave) enclaveclient.EnclaveClient {
		pool, err := enclaveclient.NewPoolWithConfig(
			nodes,
			&mockAllEnclaveSelector{},
			nil,
			enclaveclient.PoolConfig{
				Cache:                    defaultCacheConfig(),
				Session:                  enclaveclient.DefaultSessionConfig,
				RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
			},
		)
		require.NoError(t, err)
		return pool
	}

	t.Run("returns each enclave config ordered like the node list", func(t *testing.T) {
		t.Parallel()
		serverA := newConfigServer(configA)
		defer serverA.Close()
		serverB := newConfigServer(configB)
		defer serverB.Close()

		nodes := []types.Enclave{
			fixture.createNode(serverA.URL, fixture.EnclaveID1),
			fixture.createNode(serverB.URL, fixture.EnclaveID2),
		}

		configs, err := newPool(t, nodes).GetConfigs(context.Background())
		require.NoError(t, err)
		require.Len(t, configs, 2)
		assert.Equal(t, configA.Signers, configs[0].Signers)
		assert.Equal(t, configB.Signers, configs[1].Signers)
		assert.Equal(t, uint32(1), configs[0].F)
	})

	t.Run("returns an error when any enclave fetch fails", func(t *testing.T) {
		t.Parallel()
		serverA := newConfigServer(configA)
		defer serverA.Close()
		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer badServer.Close()

		nodes := []types.Enclave{
			fixture.createNode(serverA.URL, fixture.EnclaveID1),
			fixture.createNode(badServer.URL, fixture.EnclaveID2),
		}

		configs, err := newPool(t, nodes).GetConfigs(context.Background())
		require.Error(t, err)
		assert.Nil(t, configs)
	})

	t.Run("errors when the pool has no enclaves", func(t *testing.T) {
		t.Parallel()
		configs, err := newPool(t, nil).GetConfigs(context.Background())
		require.Error(t, err)
		assert.Nil(t, configs)
	})
}

func TestRequestTimeoutResolver(t *testing.T) {
	t.Parallel()

	fixture := newTestFixture(t)
	var resolverCalls atomic.Int32

	blockingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer blockingServer.Close()

	pool, err := enclaveclient.NewPoolWithConfig(
		[]types.Enclave{fixture.createNode(blockingServer.URL, fixture.EnclaveID1)},
		&mockAllEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:   defaultCacheConfig(),
			Session: enclaveclient.DefaultSessionConfig,
			RequestTimeoutResolverFn: func(ctx context.Context, publicKey bool) (time.Duration, error) {
				resolverCalls.Add(1)
				assert.False(t, publicKey)
				return 100 * time.Millisecond, nil
			},
		},
	)
	require.NoError(t, err)

	start := time.Now()
	_, err = pool.GetConfigs(context.Background())
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, int32(1), resolverCalls.Load())

	_, err = pool.GetConfigs(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(2), resolverCalls.Load(), "resolver should run on each call")
}

// TestEnclaveRequestTimeout covers the per-request enclave timeout: the pool
// applies the configured timeout to each enclave request/response call, so a
// slow enclave aborts on the configured timeout instead of blocking. GetConfigs
// is used as the representative call; ExecuteBatch and UpdateConfig apply the
// same timeout at their entry points.
func TestEnclaveRequestTimeout(t *testing.T) {
	t.Parallel()

	fixture := newTestFixture(t)

	newPoolWithTimeout := func(t *testing.T, nodes []types.Enclave, timeout time.Duration) enclaveclient.EnclaveClient {
		pool, err := enclaveclient.NewPoolWithConfig(
			nodes,
			&mockAllEnclaveSelector{},
			nil,
			enclaveclient.PoolConfig{
				Cache:                    defaultCacheConfig(),
				Session:                  enclaveclient.DefaultSessionConfig,
				RequestTimeoutResolverFn: staticRequestTimeoutResolver(timeout),
			},
		)
		require.NoError(t, err)
		return pool
	}

	t.Run("aborts on the enclave request timeout when the enclave is slow", func(t *testing.T) {
		t.Parallel()

		// The server never responds on its own; it returns only once the client
		// cancels the request. With the per-request timeout applied to this call,
		// GetConfigs aborts at ~requestTimeout and returns quickly.
		const requestTimeout = 100 * time.Millisecond

		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done(): // client's per-call timeout fired
			case <-time.After(5 * time.Second): // safety cap so a broken test can't hang
			}
		}))
		defer slowServer.Close()

		nodes := []types.Enclave{fixture.createNode(slowServer.URL, fixture.EnclaveID1)}
		pool := newPoolWithTimeout(t, nodes, requestTimeout)

		start := time.Now()
		configs, err := pool.GetConfigs(context.Background())
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.Nil(t, configs)
		// Generous upper bound (still well under serverDelay) to avoid CI flakiness
		// while proving the per-call timeout fired rather than the server response.
		assert.Less(t, elapsed, time.Second, "GetConfigs should abort on the enclave request timeout, not wait for the slow server")
	})

	t.Run("succeeds when the enclave responds within the timeout", func(t *testing.T) {
		t.Parallel()

		fastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := types.PublicKeyResponse{
				PublicKeys:  [][]byte{fixture.EphemeralPublicKey},
				Attestation: fixture.Attestation,
				Config:      types.EnclaveConfig{Signers: [][]byte{[]byte("signer")}, F: 1},
			}
			require.NoError(t, json.NewEncoder(w).Encode(&resp))
		}))
		defer fastServer.Close()

		nodes := []types.Enclave{fixture.createNode(fastServer.URL, fixture.EnclaveID1)}
		pool := newPoolWithTimeout(t, nodes, 5*time.Second)

		configs, err := pool.GetConfigs(context.Background())
		require.NoError(t, err)
		require.Len(t, configs, 1)
		assert.Equal(t, uint32(1), configs[0].F)
	})
}

func TestGetPublicKeysAuthHeader(t *testing.T) {
	t.Parallel()

	testRequestID := sha256.Sum256([]byte("test-request-id"))
	testEphemeralPublicKey := []byte("0x123456")
	testAttestation := []byte(types.FakeAttestationDocument)
	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:  [][]byte{testEphemeralPublicKey},
		Config:      testEnclaveConfig(),
		Attestation: testAttestation,
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("requestID"))

		// Verify auth header is present and correct
		assert.Equal(t, "secret-token-123", r.Header.Get("Authorization"))

		resp := &testPublicKeyResponse
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	fixture := newTestFixture(t)
	nodes := fixture.createNodes(mockServer.URL, 2)
	nodes[0].EnclaveAuthHeader = "Authorization: secret-token-123"
	nodes[1].EnclaveAuthHeader = "Authorization: secret-token-123"

	config := defaultCacheConfig()

	pool, err := newTestPoolWithCache(
		nodes,
		&mockAllEnclaveSelector{},
		nil,
		config,
	)
	require.NoError(t, err)

	resp, err := pool.GetPublicKeys(context.Background(), testRequestID, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 2, len(resp))
	for i := range resp {
		assert.Equal(t, 1, len(resp[i].PublicKeys))
		assert.Equal(t, testEphemeralPublicKey, resp[i].PublicKeys[0])
		assert.Equal(t, testAttestation, resp[i].Attestation)
	}
}

func TestExecuteBatchConcurrent(t *testing.T) {
	t.Parallel()

	testRequestID := sha256.Sum256([]byte("test-request-id"))
	testPublicData := []byte("test-output")
	testEnclaveID1 := sha256.Sum256([]byte("test-enclave-id-1"))
	testEnclaveID2 := sha256.Sum256([]byte("test-enclave-id-2"))
	testEphemeralPublicKey := []byte("0x123456")
	testAttestation := []byte(types.FakeAttestationDocument)
	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:  [][]byte{testEphemeralPublicKey},
		Config:      testEnclaveConfig(),
		Attestation: testAttestation,
	}
	testMetrics := map[string]any{
		"request_started":   map[string]any{"endpoint": "execute"},
		"request_completed": map[string]any{"endpoint": "execute", "duration_seconds": 0.1},
	}
	testExecuteResponse := &types.ExecuteResponse{
		RequestID:   testRequestID,
		Output:      testPublicData,
		Attestation: testAttestation,
		Metrics:     testMetrics,
	}

	var (
		arrived sync.WaitGroup
		release = make(chan struct{})
	)
	arrived.Add(2)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PublicKeyPath {
			resp := &testPublicKeyResponse
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			return
		}

		assert.Equal(t, "/requests", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify auth header is present and correct
		assert.Equal(t, "secret-token-123", r.Header.Get("Authorization"))

		arrived.Done()
		<-release

		var reqBody types.SignedComputeRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		resp := testExecuteResponse
		resp.RequestHash = reqBody.Hash()
		err = json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	fixture := newTestFixture(t)

	config := defaultCacheConfig()

	// Create nodes with auth header
	nodes := fixture.createNodes(mockServer.URL, 2)
	nodes[0].EnclaveAuthHeader = "Authorization: secret-token-123"
	nodes[1].EnclaveAuthHeader = "Authorization: secret-token-123"

	pool, err := newTestPoolWithCache(
		nodes,
		&mockAllEnclaveSelector{},
		nil,
		config,
	)
	require.NoError(t, err)

	pubKeyData, err := pool.GetPublicKeys(context.Background(), testRequestID, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKeyData)
	assert.Equal(t, 2, len(pubKeyData))
	assert.Equal(t, 1, len(pubKeyData[0].PublicKeys))
	assert.Equal(t, 1, len(pubKeyData[1].PublicKeys))
	assert.Equal(t, testEphemeralPublicKey, pubKeyData[0].PublicKeys[0])
	assert.Equal(t, testEphemeralPublicKey, pubKeyData[1].PublicKeys[0])

	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 testRequestID,
			PublicData:                testPublicData,
			EnclaveEphemeralPublicKey: testEphemeralPublicKey,
		},
	}

	done := make(chan struct{})
	go func() {
		resp, err := pool.ExecuteBatch(context.Background(),
			[]types.SignedComputeRequest{req, req},
			[][32]byte{testEnclaveID1, testEnclaveID2},
		)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 2, len(resp))
		for i := range resp {
			assert.Equal(t, testRequestID, resp[i].RequestID)
			assert.Equal(t, testPublicData, []byte(resp[i].Output))
			assert.Equal(t, testAttestation, resp[i].Attestation)
			// Verify metrics are passed through with correct content
			require.NotNil(t, resp[i].Metrics)
			// Verify request_started content matches what mock sent
			requestStarted, ok := resp[i].Metrics["request_started"].(map[string]any)
			require.True(t, ok, "request_started should be a map")
			assert.Equal(t, "execute", requestStarted["endpoint"])
			// Verify request_completed content matches what mock sent
			requestCompleted, ok := resp[i].Metrics["request_completed"].(map[string]any)
			require.True(t, ok, "request_completed should be a map")
			assert.Equal(t, "execute", requestCompleted["endpoint"])
			assert.Equal(t, 0.1, requestCompleted["duration_seconds"])
		}
		done <- struct{}{}
	}()

	waitCh := make(chan struct{})
	go func() {
		arrived.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for both handlers to arrive (concurrency likely broken)")
	}

	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ExecuteBatch to finish")
	}
}

func TestExecute_Error(t *testing.T) {
	t.Parallel()

	testEphemeralPulicKey := []byte("0x123456")
	testAttestation := []byte(types.FakeAttestationDocument)
	testPublicData := []byte("test-output")
	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:  [][]byte{testEphemeralPulicKey},
		Config:      testEnclaveConfig(),
		Attestation: testAttestation,
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PublicKeyPath {
			resp := &testPublicKeyResponse
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(`{"error": "internal error"}`))
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	fixture := newTestFixture(t)
	testEnclaveID := sha256.Sum256([]byte("test-enclave-id"))
	nodes := []types.Enclave{
		{
			EnclaveID:     testEnclaveID,
			EnclaveURL:    mockServer.URL,
			EnclaveType:   types.EnclaveTypeFake,
			TrustedValues: [][]byte{[]byte("foobar"), fixture.TrustedMeasurements},
		},
	}

	testRequestID := sha256.Sum256([]byte("test-request"))
	pool, err := newTestPool(nodes, nil, nil)
	require.NoError(t, err)
	req := &types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 testRequestID,
			PublicData:                testPublicData,
			EnclaveEphemeralPublicKey: testEphemeralPulicKey,
		},
	}

	pubKeyData, err := pool.GetPublicKeys(context.Background(), testRequestID, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKeyData)
	assert.Equal(t, 1, len(pubKeyData))
	assert.Equal(t, 1, len(pubKeyData[0].PublicKeys))
	assert.Equal(t, testEphemeralPulicKey, pubKeyData[0].PublicKeys[0])

	resp, err := pool.ExecuteBatch(context.Background(), []types.SignedComputeRequest{*req}, [][32]byte{testEnclaveID})
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "execute failed")
}

func TestExecute_MalformedAuthHeader(t *testing.T) {
	t.Parallel()

	testEphemeralPublicKey := []byte("0x123456")
	testAttestation := []byte(types.FakeAttestationDocument)
	testPublicData := []byte("test-output")
	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:  [][]byte{testEphemeralPublicKey},
		Config:      testEnclaveConfig(),
		Attestation: testAttestation,
	}

	fixture := newTestFixture(t)
	testEnclaveID := sha256.Sum256([]byte("test-enclave-id"))

	testCases := []struct {
		name       string
		authHeader string
		wantErr    string
	}{
		{
			name:       "missing colon",
			authHeader: "AuthorizationBearer token",
			wantErr:    "malformed enclave auth header",
		},
		{
			name:       "too many colons",
			authHeader: "Authorization:Bearer:token",
			wantErr:    "malformed enclave auth header",
		},
		{
			name:       "empty string should skip header",
			authHeader: "",
			wantErr:    "", // Empty string should not error, it just skips setting header
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testRequestID := sha256.Sum256([]byte("test-request-" + tc.name))
			testExecuteResponse := &types.ExecuteResponse{
				RequestID:   testRequestID,
				Output:      testPublicData,
				Attestation: testAttestation,
			}

			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == types.PublicKeyPath {
					resp := &testPublicKeyResponse
					err := json.NewEncoder(w).Encode(resp)
					require.NoError(t, err)
					return
				}

				// For empty auth header case, verify no auth header is sent
				if tc.authHeader == "" {
					assert.Empty(t, r.Header.Get("Authorization"))
				}

				var reqBody types.SignedComputeRequest
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				require.NoError(t, err)

				resp := testExecuteResponse
				resp.RequestHash = reqBody.Hash()
				err = json.NewEncoder(w).Encode(&resp)
				require.NoError(t, err)
			}))
			defer mockServer.Close()

			nodes := []types.Enclave{
				{
					EnclaveID:         testEnclaveID,
					EnclaveURL:        mockServer.URL,
					EnclaveType:       types.EnclaveTypeFake,
					TrustedValues:     [][]byte{fixture.TrustedMeasurements},
					EnclaveAuthHeader: tc.authHeader,
				},
			}

			pool, err := newTestPool(nodes, nil, nil)
			require.NoError(t, err)

			req := &types.SignedComputeRequest{
				ComputeRequest: types.ComputeRequest{
					RequestID:                 testRequestID,
					PublicData:                testPublicData,
					EnclaveEphemeralPublicKey: testEphemeralPublicKey,
				},
			}

			resp, err := pool.ExecuteBatch(context.Background(), []types.SignedComputeRequest{*req}, [][32]byte{testEnclaveID})

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				require.Nil(t, resp)
			} else {
				// Empty auth header should succeed
				require.NoError(t, err)
				require.NotNil(t, resp)
			}
		})
	}
}

func TestCacheBasicFunctionality(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	// First call should hit server
	resp1, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, resp1, 1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	// Second call should also hit server (network-first strategy)
	testRequestID2 := sha256.Sum256([]byte("different-request-id"))
	resp2, err := pool.GetPublicKeys(context.Background(), testRequestID2, nil)
	require.NoError(t, err)
	require.Len(t, resp2, 1)
	assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))

	assert.Equal(t, resp1[0].PublicKeys, resp2[0].PublicKeys)
	assert.Equal(t, resp1[0].EnclaveID, resp2[0].EnclaveID)
}

func TestCacheWithEnclaveTTL(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount, 100*time.Millisecond)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	time.Sleep(150 * time.Millisecond)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))
}

func TestCacheDisabled(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	config := defaultCacheConfig()
	config.EnableCache = false

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		config,
	)
	require.NoError(t, err)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))
}

func TestCacheStats(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	mockServer := createMockServer(t, fixture, nil)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	stats := pool.GetCacheStats()
	assert.True(t, stats["cache_enabled"].(bool))
	assert.Equal(t, 0, stats["item_count"].(int))

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)

	stats = pool.GetCacheStats()
	assert.Equal(t, 1, stats["item_count"].(int))
	assert.Equal(t, 30*60.0, stats["max_ttl_seconds"].(float64))
	assert.Equal(t, 0.1, stats["ttl_buffer_percent"].(float64))
}

func TestCacheNodeUpdate(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	stats := pool.GetCacheStats()
	assert.Equal(t, 1, stats["item_count"].(int))

	// Update with different nodes (2 instead of 1) to trigger cache flush.
	// UpdateNodes validates each of the 2 new nodes with a publicKeys fetch.
	require.NoError(t, pool.UpdateNodes(context.Background(), fixture.createNodes(mockServer.URL, 2)))
	assert.Equal(t, int32(3), atomic.LoadInt32(&requestCount))

	stats = pool.GetCacheStats()
	assert.Equal(t, 0, stats["item_count"].(int))

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(4), atomic.LoadInt32(&requestCount))

	stats = pool.GetCacheStats()
	assert.Equal(t, 1, stats["item_count"].(int))

	// Idempotent update with same nodes should NOT flush cache or re-validate
	require.NoError(t, pool.UpdateNodes(context.Background(), fixture.createNodes(mockServer.URL, 2)))
	assert.Equal(t, int32(4), atomic.LoadInt32(&requestCount), "idempotent update must not fetch")

	stats = pool.GetCacheStats()
	assert.Equal(t, 1, stats["item_count"].(int), "cache should not be flushed on idempotent update")

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(5), atomic.LoadInt32(&requestCount), "network-first: should always fetch from server")
}

func TestCacheMultipleTTLs(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	// Mock server that returns multiple TTLs
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		resp := types.PublicKeyResponse{
			PublicKeys:    [][]byte{fixture.EphemeralPublicKey, fixture.EphemeralPublicKey},
			CreationTimes: []time.Time{time.Now(), time.Now()},
			TTLs:          []time.Duration{5 * time.Minute, 2 * time.Minute}, // Different TTLs
			Config:        testEnclaveConfig(),
			Attestation:   fixture.Attestation,
		}

		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	// First call should use shorter TTL (2 minutes with 10% buffer)
	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	// Immediate second call should also hit server (network-first strategy)
	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))
}

func TestCacheFallbackOnNetworkFailure(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32
	var shouldFail atomic.Bool

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		if shouldFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := fixture.createPublicKeyResponse(5 * time.Minute)
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	// First call succeeds and populates cache
	resp1, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, resp1, 1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	// Server starts failing
	shouldFail.Store(true)

	// Second call should fail the network fetch but fall back to cache
	resp2, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, resp2, 1)
	assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))

	assert.Equal(t, resp1[0].PublicKeys, resp2[0].PublicKeys)
	assert.Equal(t, resp1[0].EnclaveID, resp2[0].EnclaveID)
}

func TestCacheFallbackOnNetworkFailure_NoCacheEntry(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	// Server always fails - no cached entry exists
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		defaultCacheConfig(),
	)
	require.NoError(t, err)

	// Should return error since network fails and there's nothing in cache
	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.Error(t, err)
}

func TestProactiveCacheDisabled(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	config := defaultCacheConfig()
	config.EnableProactiveRefresh = false

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		config,
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount))

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

	stats := pool.GetCacheStats()
	assert.False(t, stats["proactive_refresh_enabled"].(bool))
}

func TestGetPublicKeys_ProactiveRefreshDisabled_DoesNotSkipInitialSelection(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	selector := enclaveselector.NewRoundRobinEnclaveSelector()

	deadNodes := []types.Enclave{
		fixture.createNode("", fixture.EnclaveID1),
		fixture.createNode("", fixture.EnclaveID2),
	}
	selected, err := selector.SelectEnclaves(deadNodes, fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	var deadCount int32
	var liveCount int32

	deadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&deadCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer deadServer.Close()

	liveServer := createMockServer(t, fixture, &liveCount)
	defer liveServer.Close()

	node1URL := liveServer.URL
	node2URL := liveServer.URL
	if selected[0].EnclaveID == fixture.EnclaveID1 {
		node1URL = deadServer.URL
	} else {
		node2URL = deadServer.URL
	}

	config := defaultCacheConfig()
	config.EnableProactiveRefresh = false

	pool, err := newTestPoolWithCache(
		[]types.Enclave{
			fixture.createNode(node1URL, fixture.EnclaveID1),
			fixture.createNode(node2URL, fixture.EnclaveID2),
		},
		selector,
		nil,
		config,
	)
	require.NoError(t, err)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deadCount))
	assert.Equal(t, int32(0), atomic.LoadInt32(&liveCount))
}

func TestGetPublicKeys_SkipsDeadEnclaveFromRefresh(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	selector := enclaveselector.NewRoundRobinEnclaveSelector()

	baseNodes := []types.Enclave{
		fixture.createNode("", fixture.EnclaveID1),
		fixture.createNode("", fixture.EnclaveID2),
	}
	selected, err := selector.SelectEnclaves(baseNodes, fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	var deadCount int32
	var liveCount int32

	deadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&deadCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer deadServer.Close()

	liveServer := createMockServer(t, fixture, &liveCount)
	defer liveServer.Close()

	var node1URL string
	var node2URL string
	var liveEnclaveID [32]byte
	if selected[0].EnclaveID == fixture.EnclaveID1 {
		node1URL = deadServer.URL
		node2URL = liveServer.URL
		liveEnclaveID = fixture.EnclaveID2
	} else {
		node1URL = liveServer.URL
		node2URL = deadServer.URL
		liveEnclaveID = fixture.EnclaveID1
	}

	pool, err := newTestPoolWithCache(
		[]types.Enclave{
			fixture.createNode(node1URL, fixture.EnclaveID1),
			fixture.createNode(node2URL, fixture.EnclaveID2),
		},
		selector,
		nil,
		proactiveCacheConfig(5*time.Minute, 0.6),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	resp, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, liveEnclaveID, resp[0].EnclaveID)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deadCount), "dead enclave should only be contacted during warmup")
	assert.Equal(t, int32(2), atomic.LoadInt32(&liveCount), "live enclave should serve warmup and request-path fetch")
}

func TestGetPublicKeys_DeadEnclaveBecomesSelectableAfterSuccessfulRefresh(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	selector := enclaveselector.NewRoundRobinEnclaveSelector()

	baseNodes := []types.Enclave{
		fixture.createNode("", fixture.EnclaveID1),
		fixture.createNode("", fixture.EnclaveID2),
	}
	selected, err := selector.SelectEnclaves(baseNodes, fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	var recoveringCount int32
	var stableCount int32

	recoveringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&recoveringCount, 1)
		if call == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp := fixture.createPublicKeyResponse(400 * time.Millisecond)
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer recoveringServer.Close()

	stableServer := createMockServer(t, fixture, &stableCount, 400*time.Millisecond)
	defer stableServer.Close()

	var node1URL string
	var node2URL string
	var recoveredEnclaveID [32]byte
	var stableEnclaveID [32]byte
	if selected[0].EnclaveID == fixture.EnclaveID1 {
		node1URL = recoveringServer.URL
		node2URL = stableServer.URL
		recoveredEnclaveID = fixture.EnclaveID1
		stableEnclaveID = fixture.EnclaveID2
	} else {
		node1URL = stableServer.URL
		node2URL = recoveringServer.URL
		recoveredEnclaveID = fixture.EnclaveID2
		stableEnclaveID = fixture.EnclaveID1
	}

	pool, err := newTestPoolWithCache(
		[]types.Enclave{
			fixture.createNode(node1URL, fixture.EnclaveID1),
			fixture.createNode(node2URL, fixture.EnclaveID2),
		},
		selector,
		nil,
		proactiveCacheConfig(400*time.Millisecond, 0.5),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	initialResp, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, initialResp, 1)
	assert.Equal(t, stableEnclaveID, initialResp[0].EnclaveID)

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&recoveringCount) >= 2
	}, 2*time.Second, 25*time.Millisecond)

	recoveredResp, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.Len(t, recoveredResp, 1)
	assert.Equal(t, recoveredEnclaveID, recoveredResp[0].EnclaveID)
}

func TestProactiveCachePeriodicRefresh(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount, 200*time.Millisecond)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockAllEnclaveSelector{},
		nil,
		proactiveCacheConfig(200*time.Millisecond, 0.5),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	time.Sleep(100 * time.Millisecond)
	initialCount := atomic.LoadInt32(&requestCount)
	assert.GreaterOrEqual(t, initialCount, int32(1))

	time.Sleep(150 * time.Millisecond)
	finalCount := atomic.LoadInt32(&requestCount)
	assert.Greater(t, finalCount, initialCount)
}

func TestProactiveCacheMultipleEnclaves(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 2),
		&mockAllEnclaveSelector{},
		nil,
		proactiveCacheConfig(5*time.Minute, 0.6),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	time.Sleep(200 * time.Millisecond)

	count := atomic.LoadInt32(&requestCount)
	assert.GreaterOrEqual(t, count, int32(2))

	stats := pool.GetCacheStats()
	assert.Equal(t, 2, stats["item_count"].(int))
	assert.Equal(t, 2, stats["fresh_enclaves"].(int))
	assert.Equal(t, 0, stats["stale_enclaves"].(int))
}

func TestProactiveCacheUpdateNodesTriggersRefresh(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var requestCount int32

	mockServer := createMockServer(t, fixture, &requestCount)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockAllEnclaveSelector{},
		nil,
		proactiveCacheConfig(5*time.Minute, 0.6),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	time.Sleep(200 * time.Millisecond)
	countAfterWarmup := atomic.LoadInt32(&requestCount)
	assert.GreaterOrEqual(t, countAfterWarmup, int32(1))

	require.NoError(t, pool.UpdateNodes(context.Background(), fixture.createNodes(mockServer.URL, 2)))
	time.Sleep(200 * time.Millisecond)

	countAfterUpdate := atomic.LoadInt32(&requestCount)
	assert.Greater(t, countAfterUpdate, countAfterWarmup)

	stats := pool.GetCacheStats()
	assert.Equal(t, 2, stats["item_count"].(int))
}

func TestProactiveCacheStatsTracking(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	mockServer := createMockServer(t, fixture, nil)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockAllEnclaveSelector{},
		nil,
		proactiveCacheConfig(5*time.Minute, 0.6),
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	time.Sleep(200 * time.Millisecond)

	stats := pool.GetCacheStats()
	assert.True(t, stats["proactive_refresh_enabled"].(bool))
	assert.Equal(t, 1, stats["fresh_enclaves"].(int))
	assert.Equal(t, 0, stats["stale_enclaves"].(int))

	// Check refresh interval is calculated correctly
	// 60% of 5 minutes = 3 minutes = 180 seconds
	expectedInterval := 180.0
	assert.Equal(t, expectedInterval, stats["refresh_interval_seconds"].(float64))
}

func TestProactiveCacheGracefulShutdown(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	mockServer := createMockServer(t, fixture, nil)
	defer mockServer.Close()

	pool, err := newTestPoolWithCache(
		fixture.createNodes(mockServer.URL, 1),
		&mockAllEnclaveSelector{},
		nil,
		proactiveCacheConfig(5*time.Minute, 0.6),
	)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = pool.Close()
	require.NoError(t, err)

	err = pool.Close()
	require.NoError(t, err)
}

func TestSessionPersistence(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	// We'll use this key to verify persistence
	sessionHeaderName := "x-session-id"
	sessionID1 := "session-123"
	sessionID2 := "session-456"

	var (
		mu           sync.Mutex
		lastReceived string
	)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastReceived = r.Header.Get(sessionHeaderName)
		mu.Unlock()

		// Set the header in response
		// For first request, we set sessionID1
		// If client sent sessionID1, we update it to sessionID2 to test update logic
		if r.Header.Get(sessionHeaderName) == sessionID1 {
			w.Header().Set(sessionHeaderName, sessionID2)
		} else {
			w.Header().Set(sessionHeaderName, sessionID1)
		}

		if r.URL.Path == types.PublicKeyPath {
			resp := &types.PublicKeyResponse{
				PublicKeys:    [][]byte{fixture.EphemeralPublicKey},
				Attestation:   fixture.Attestation,
				TTLs:          []time.Duration{time.Minute},
				CreationTimes: []time.Time{time.Now()},
				Config:        testEnclaveConfig(),
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			return
		}

		if r.URL.Path == types.ExecutePath {
			var reqBody types.SignedComputeRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)

			resp := &types.ExecuteResponse{
				RequestID:   reqBody.RequestID,
				Output:      fixture.PublicData,
				Attestation: fixture.Attestation,
				RequestHash: reqBody.Hash(),
			}
			err = json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			return
		}
	}))
	defer mockServer.Close()

	config := defaultCacheConfig()
	// Disable cache so we always hit the server to verify headers
	config.EnableCache = false

	poolConfig := enclaveclient.PoolConfig{
		Cache: config,
		Session: enclaveclient.SessionConfig{
			EnableSessionPersistence: true,
			SessionHeaderName:        sessionHeaderName,
		},
		RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
	}

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		poolConfig,
	)
	require.NoError(t, err)

	// 1. First call to GetPublicKeys - should receive sessionID1
	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)

	mu.Lock()
	assert.Empty(t, lastReceived) // First request has no session
	mu.Unlock()

	// 2. ExecuteBatch - should send sessionID1 and receive sessionID2
	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 fixture.RequestID,
			PublicData:                fixture.PublicData,
			EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
		},
	}

	resps, err := pool.ExecuteBatch(context.Background(),
		[]types.SignedComputeRequest{req},
		[][32]byte{fixture.EnclaveID1}, // Using EnclaveID1 which matches the node created by fixture
	)
	require.NoError(t, err)
	require.Len(t, resps, 1)

	mu.Lock()
	assert.Equal(t, sessionID1, lastReceived)
	mu.Unlock()
}

func TestExecuteBatchRejectsMismatchedApplicationRequestIDForNonLegacy(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != types.ExecutePath {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var reqBody types.SignedComputeRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		resp := &types.ExecuteResponse{
			RequestID:            reqBody.RequestID,
			ApplicationRequestID: "different-application-request-id",
			Output:               fixture.PublicData,
			Attestation:          fixture.Attestation,
			RequestHash:          reqBody.Hash(),
		}
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    defaultCacheConfig(),
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 fixture.RequestID,
			ApplicationRequestID:      "application-request-id",
			PublicData:                fixture.PublicData,
			EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
			Version:                   "0.0.7",
		},
	}

	resp, err := pool.ExecuteBatch(context.Background(), []types.SignedComputeRequest{req}, [][32]byte{fixture.EnclaveID1})
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "mismatched application request ID")
}

// Mock metrics emitter for testing
type mockMetricsEmitter struct {
	mu          sync.Mutex
	emitRecords map[string][]map[string]any
}

func newMockMetricsEmitter() *mockMetricsEmitter {
	return &mockMetricsEmitter{
		emitRecords: make(map[string][]map[string]any),
	}
}

func (m *mockMetricsEmitter) Emit(event string, details map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emitRecords[event] = append(m.emitRecords[event], details)
}

func (m *mockMetricsEmitter) getRecords(event string) []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.emitRecords[event]
}

func TestExecuteBatch_ForwardsEnclaveMetricsFromErrorResponse(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:    [][]byte{fixture.EphemeralPublicKey},
		CreationTimes: []time.Time{time.Now()},
		TTLs:          []time.Duration{5 * time.Minute},
		Config:        testEnclaveConfig(),
		Attestation:   fixture.Attestation,
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PublicKeyPath {
			err := json.NewEncoder(w).Encode(&testPublicKeyResponse)
			require.NoError(t, err)
			return
		}

		// Simulate enclave returning a JSON error response with metrics
		// (e.g. attestation_creation_failed inside the enclave)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "error creating attestation: nitro attestation service unavailable",
			"metrics": map[string]any{
				"attestation_creation_failed": map[string]any{
					"endpoint": "execute",
					"error":    "nitro attestation service unavailable",
				},
				"app_execution_completed": map[string]any{
					"duration_seconds": 0.5,
				},
			},
		})
	}))
	defer mockServer.Close()

	mockMetrics := newMockMetricsEmitter()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    defaultCacheConfig(),
			Metrics:                  mockMetrics,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	// Get public keys first
	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)

	// ExecuteBatch should fail but forward the enclave metrics
	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 fixture.RequestID,
			PublicData:                fixture.PublicData,
			EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
		},
	}

	resp, err := pool.ExecuteBatch(context.Background(),
		[]types.SignedComputeRequest{req},
		[][32]byte{fixture.EnclaveID1},
	)
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "execute failed")
	assert.Contains(t, err.Error(), "nitro attestation service unavailable")
	assert.NotContains(t, err.Error(), "metrics")

	// Verify enclave metrics were forwarded without a name prefix
	attestRecords := mockMetrics.getRecords("attestation_creation_failed")
	require.Len(t, attestRecords, 1)
	assert.Equal(t, "execute", attestRecords[0]["endpoint"])
	assert.Equal(t, "nitro attestation service unavailable", attestRecords[0]["error"])

	appRecords := mockMetrics.getRecords("app_execution_completed")
	require.Len(t, appRecords, 1)
	assert.Equal(t, 0.5, appRecords[0]["duration_seconds"])
	assert.Equal(t, "enclave", appRecords[0]["component"])
}

func TestExecuteBatch_PlainTextErrorNoMetricsPanic(t *testing.T) {
	// Verify pool handles plain text (non-JSON) error responses gracefully
	// without panicking or emitting spurious metrics.
	t.Parallel()
	fixture := newTestFixture(t)

	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:    [][]byte{fixture.EphemeralPublicKey},
		CreationTimes: []time.Time{time.Now()},
		TTLs:          []time.Duration{5 * time.Minute},
		Config:        testEnclaveConfig(),
		Attestation:   fixture.Attestation,
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PublicKeyPath {
			err := json.NewEncoder(w).Encode(&testPublicKeyResponse)
			require.NoError(t, err)
			return
		}

		// Plain text error (old-style http.Error response)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	mockMetrics := newMockMetricsEmitter()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    defaultCacheConfig(),
			Metrics:                  mockMetrics,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)

	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 fixture.RequestID,
			PublicData:                fixture.PublicData,
			EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
		},
	}

	resp, err := pool.ExecuteBatch(context.Background(),
		[]types.SignedComputeRequest{req},
		[][32]byte{fixture.EnclaveID1},
	)
	require.Error(t, err)
	require.Nil(t, resp)

	// No enclave metrics should be emitted for plain text errors
	assert.Empty(t, mockMetrics.getRecords("attestation_creation_failed"))
}

func TestExecuteBatch_ErrorResponseIntegration(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:    [][]byte{fixture.EphemeralPublicKey},
		CreationTimes: []time.Time{time.Now()},
		TTLs:          []time.Duration{5 * time.Minute},
		Config:        testEnclaveConfig(),
		Attestation:   fixture.Attestation,
	}

	makePool := func(t *testing.T, handler http.HandlerFunc) (*mockMetricsEmitter, enclaveclient.EnclaveClient) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == types.PublicKeyPath {
				err := json.NewEncoder(w).Encode(&testPublicKeyResponse)
				require.NoError(t, err)
				return
			}
			handler(w, r)
		}))
		t.Cleanup(mockServer.Close)

		mockMetrics := newMockMetricsEmitter()
		pool, err := enclaveclient.NewPoolWithConfig(
			fixture.createNodes(mockServer.URL, 1),
			&mockSingleEnclaveSelector{},
			nil,
			enclaveclient.PoolConfig{
				Cache:                    defaultCacheConfig(),
				Metrics:                  mockMetrics,
				RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
			},
		)
		require.NoError(t, err)

		_, err = pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
		require.NoError(t, err)
		return mockMetrics, pool
	}

	executeAndExpectError := func(t *testing.T, pool enclaveclient.EnclaveClient) error {
		req := types.SignedComputeRequest{
			ComputeRequest: types.ComputeRequest{
				RequestID:                 fixture.RequestID,
				PublicData:                fixture.PublicData,
				EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
			},
		}
		resp, err := pool.ExecuteBatch(context.Background(),
			[]types.SignedComputeRequest{req},
			[][32]byte{fixture.EnclaveID1},
		)
		require.Error(t, err)
		require.Nil(t, resp)
		return err
	}

	t.Run("JSON error with metrics", func(t *testing.T) {
		t.Parallel()
		mockMetrics, pool := makePool(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(types.EnclaveErrorResponse{
				Error: "error creating attestation: nitro attestation service unavailable",
				Metrics: map[string]any{
					"attestation_creation_failed": map[string]any{
						"endpoint": "execute",
						"error":    "nitro attestation service unavailable",
					},
				},
			})
		})

		err := executeAndExpectError(t, pool)
		assert.Contains(t, err.Error(), "nitro attestation service unavailable")
		assert.NotContains(t, err.Error(), "metrics")
		assert.NotContains(t, err.Error(), "attestation_creation_failed")

		records := mockMetrics.getRecords("attestation_creation_failed")
		require.Len(t, records, 1)
		assert.Equal(t, "execute", records[0]["endpoint"])
		assert.Equal(t, "nitro attestation service unavailable", records[0]["error"])
	})

	t.Run("plain text error (backwards compat)", func(t *testing.T) {
		t.Parallel()
		mockMetrics, pool := makePool(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		})

		err := executeAndExpectError(t, pool)
		assert.Contains(t, err.Error(), "internal error")

		// No enclave metrics should be emitted for plain text errors
		assert.Empty(t, mockMetrics.getRecords("attestation_creation_failed"))
	})

	t.Run("JSON error without metrics field", func(t *testing.T) {
		t.Parallel()
		mockMetrics, pool := makePool(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(types.EnclaveErrorResponse{
				Error: "missing AppID in request",
			})
		})

		err := executeAndExpectError(t, pool)
		assert.Contains(t, err.Error(), "missing AppID in request")
		assert.NotContains(t, err.Error(), "metrics")

		// No metrics should be emitted
		assert.Empty(t, mockMetrics.getRecords("attestation_creation_failed"))
	})

	t.Run("multiple enclave metrics in single error", func(t *testing.T) {
		t.Parallel()
		mockMetrics, pool := makePool(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(types.EnclaveErrorResponse{
				Error: "error creating attestation: service unavailable",
				Metrics: map[string]any{
					"request_started": map[string]any{
						"endpoint": "execute",
					},
					"app_execution_failed": map[string]any{
						"error":            "timeout",
						"duration_seconds": 30.0,
					},
					"attestation_creation_failed": map[string]any{
						"endpoint": "execute",
						"error":    "service unavailable",
					},
				},
			})
		})

		err := executeAndExpectError(t, pool)
		assert.Contains(t, err.Error(), "error creating attestation: service unavailable")

		// All three metrics should be forwarded
		startRecords := mockMetrics.getRecords("request_started")
		require.Len(t, startRecords, 1)
		assert.Equal(t, "execute", startRecords[0]["endpoint"])
		assert.Equal(t, "enclave", startRecords[0]["component"])

		appRecords := mockMetrics.getRecords("app_execution_failed")
		require.Len(t, appRecords, 1)
		assert.Equal(t, "timeout", appRecords[0]["error"])
		assert.Equal(t, 30.0, appRecords[0]["duration_seconds"])
		assert.Equal(t, "enclave", appRecords[0]["component"])

		attestRecords := mockMetrics.getRecords("attestation_creation_failed")
		require.Len(t, attestRecords, 1)
		assert.Equal(t, "execute", attestRecords[0]["endpoint"])
		assert.Equal(t, "enclave", attestRecords[0]["component"])
	})
}

func TestCacheRefreshFailure_EmitsMetric(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	// Stateful server: serve the valid fake attestation on the first call
	// (initial warmup succeeds), then a non-fake attestation on subsequent
	// calls so the fake validator rejects refresh attempts.
	callCount := int32(0)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		resp := fixture.createPublicKeyResponse(200 * time.Millisecond)
		if count > 1 {
			resp.Attestation = []byte("invalid")
		}
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	mockMetrics := newMockMetricsEmitter()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockAllEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    proactiveCacheConfig(200*time.Millisecond, 0.5),
			Metrics:                  mockMetrics,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)
	defer func() {
		err := pool.Close()
		require.NoError(t, err)
	}()

	// Wait for initial warmup (succeeds) + at least one refresh cycle (fails)
	time.Sleep(350 * time.Millisecond)

	records := mockMetrics.getRecords("cache_refresh_failed")
	require.NotEmpty(t, records, "cache_refresh_failed metric should have been emitted")
	assert.Contains(t, records[0]["error"], "invalid fake attestation")
	assert.NotEmpty(t, records[0]["enclave.id"])
}

func TestGetPublicKeys_AttestationValidationFailure(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	// Serve a non-fake attestation so the fake validator always rejects it.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := fixture.createPublicKeyResponse()
		resp.Attestation = []byte("invalid")
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	mockMetrics := newMockMetricsEmitter()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    defaultCacheConfig(),
			Metrics:                  mockMetrics,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	// GetPublicKeys should fail due to attestation validation failure
	resp, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "attestation validation failed")

	// Verify the metric was emitted
	records := mockMetrics.getRecords("attestation_validation_failed")
	require.Len(t, records, 1)
	assert.Equal(t, "publicKeys", records[0]["endpoint"])
	assert.Contains(t, records[0]["error"], "invalid fake attestation")
}

func TestExecuteBatch_AttestationValidationFailure(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	testPublicKeyResponse := types.PublicKeyResponse{
		PublicKeys:    [][]byte{fixture.EphemeralPublicKey},
		CreationTimes: []time.Time{time.Now()},
		TTLs:          []time.Duration{5 * time.Minute},
		Config:        testEnclaveConfig(),
		Attestation:   fixture.Attestation,
	}
	testExecuteResponse := &types.ExecuteResponse{
		RequestID: fixture.RequestID,
		Output:    fixture.PublicData,
		// publicKeys validation passes (fixture.Attestation is the fake doc),
		// but the execute response serves a tampered attestation that the fake
		// validator rejects.
		Attestation: []byte("tampered"),
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == types.PublicKeyPath {
			resp := &testPublicKeyResponse
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			return
		}

		// Execute endpoint
		var reqBody types.SignedComputeRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		resp := testExecuteResponse
		resp.RequestHash = reqBody.Hash()
		err = json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	mockMetrics := newMockMetricsEmitter()

	pool, err := enclaveclient.NewPoolWithConfig(
		fixture.createNodes(mockServer.URL, 1),
		&mockSingleEnclaveSelector{},
		nil,
		enclaveclient.PoolConfig{
			Cache:                    defaultCacheConfig(),
			Metrics:                  mockMetrics,
			RequestTimeoutResolverFn: defaultRequestTimeoutResolver(),
		},
	)
	require.NoError(t, err)

	// First, get public keys (should succeed)
	pubKeyData, err := pool.GetPublicKeys(context.Background(), fixture.RequestID, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKeyData)

	// ExecuteBatch should fail due to attestation validation failure
	req := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 fixture.RequestID,
			PublicData:                fixture.PublicData,
			EnclaveEphemeralPublicKey: fixture.EphemeralPublicKey,
		},
	}

	resp, err := pool.ExecuteBatch(context.Background(),
		[]types.SignedComputeRequest{req},
		[][32]byte{fixture.EnclaveID1},
	)
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "attestation validation failed")

	// Verify the metric was emitted
	records := mockMetrics.getRecords("attestation_validation_failed")
	require.Len(t, records, 1)
	assert.Equal(t, "execute", records[0]["endpoint"])
	assert.Contains(t, records[0]["error"], "invalid fake attestation")
}
