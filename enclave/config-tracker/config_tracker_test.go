package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewConfigTracker(t *testing.T) {
	lggr := createTestLogger(t)
	donID := uint32(123)
	hostPort := "8080"
	configPort := "8081"
	refreshInterval := 30 * time.Second
	tval := uint32(2)
	masterPublicKey := []byte("test-public-key")

	registryWrapper := &capabilities_registry_wrapper_v2.CapabilitiesRegistry{}
	tracker := NewConfigTracker(registryWrapper, lggr, donID, hostPort, configPort, refreshInterval, tval, masterPublicKey, false)

	assert.NotNil(t, tracker)
	assert.Equal(t, donID, tracker.donID)
	assert.Equal(t, hostPort, tracker.hostPort)
	assert.Equal(t, configPort, tracker.configPort)
	assert.Equal(t, refreshInterval, tracker.refreshInterval)
	assert.Equal(t, lggr, tracker.logger)
	assert.Equal(t, tval, tracker.initialT)
	assert.Equal(t, masterPublicKey, tracker.initialMasterPublicKey)
}

func TestCheckUpdates_Success_NoUpdateNeeded(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	// Mock DON data with sorted node IDs
	nodeP2PIds := [][32]byte{
		{0x01, 0x02, 0x03}, // Smaller ID first
		{0x04, 0x05, 0x06}, // Larger ID second
	}
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: nodeP2PIds,
		F:          1,
	}

	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Setup test server for enclave endpoints
	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)

		// Return matching signers (already sorted to match DON)
		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers: [][]byte{
					toBytes32([]byte{0x01, 0x02, 0x03}),
					toBytes32([]byte{0x04, 0x05, 0x06}),
				},
				MasterPublicKey: []byte("test-public-key"),
				T:               2,
				F:               1, // matches don.F = 1
			},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer publicKeysServer.Close()

	// Setup config server to track if it's called (it should NOT be called)
	configCallCount := 0
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configCallCount++
		t.Errorf("Config endpoint should not be called when signers match, but was called %d times", configCallCount)
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("Should not be called"))
		require.NoError(t, err)
	}))
	defer configServer.Close()

	// Extract ports from test server URLs
	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()

	ct := &configTracker{}
	configSet, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, configPort)

	assert.NoError(t, err)
	assert.True(t, configSet, "Config should be reported as set when signers already match")
	assert.Equal(t, 0, configCallCount, "Config endpoint should never be called when signers already match")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_Success_UpdateNeededForF(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	// Mock DON data with sorted node IDs
	nodeP2PIds := [][32]byte{
		{0x01, 0x02, 0x03}, // Smaller ID first
		{0x04, 0x05, 0x06}, // Larger ID second
	}
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: nodeP2PIds,
		F:          2,
	}

	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Setup test server for enclave endpoints
	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)

		// Return matching signers (already sorted to match DON)
		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers: [][]byte{
					toBytes32([]byte{0x01, 0x02, 0x03}),
					toBytes32([]byte{0x04, 0x05, 0x06}),
				},
				MasterPublicKey: []byte("test-public-key"),
				T:               2,
				F:               1,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer publicKeysServer.Close()

	// Setup config server to track if it's called (it should NOT be called)
	configCallCount := 0
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if configCallCount > 0 {
			t.Errorf("Config endpoint should not be called when signers match, but was called %d times", configCallCount)
		}
		configCallCount++
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		require.NoError(t, err)
	}))
	defer configServer.Close()

	// Extract ports from test server URLs
	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()

	ct := &configTracker{}
	configSet, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, configPort)

	assert.NoError(t, err)
	assert.True(t, configSet, "Config should be reported as set after a successful update")
	assert.Equal(t, 1, configCallCount, "Config endpoint should be called for F value")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_Success_UpdateNeeded(t *testing.T) {
	// Setup mock registry
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	// Mock DON data
	nodeP2PIds := [][32]byte{
		{0x07, 0x08, 0x09},
		{0x0a, 0x0b, 0x0c},
	}
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: nodeP2PIds,
		F:          1,
	}

	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Setup test server for enclave endpoints
	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)

		// Return different signers (needs update)
		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers: [][]byte{
					{0x01, 0x02, 0x03}, // Different from DON
					{0x04, 0x05, 0x06},
				},
				MasterPublicKey: []byte("test-public-key"),
				T:               2,
				F:               1,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer publicKeysServer.Close()

	configUpdateReceived := false
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/config", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		var configReq types.ConfigRequest
		err := json.NewDecoder(r.Body).Decode(&configReq)
		assert.NoError(t, err)

		var config types.EnclaveConfig
		err = json.Unmarshal(configReq.Config, &config)
		assert.NoError(t, err)

		// Verify the config contains the DON node IDs
		assert.Len(t, config.Signers, 2)
		assert.Equal(t, []byte("test-public-key"), config.MasterPublicKey)

		configUpdateReceived = true
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		require.NoError(t, err)
	}))
	defer configServer.Close()

	// Extract just the port from test server URLs
	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()

	ct := &configTracker{}
	configSet, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, configPort)

	assert.NoError(t, err)
	assert.True(t, configSet, "Config should be reported as set after a successful update")
	assert.True(t, configUpdateReceived, "Config update should have been sent")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_UnconfiguredEnclave_SetsInitialConfig(t *testing.T) {
	// An unconfigured enclave serves 503 on /publicKeys. checkUpdates must treat
	// that as an empty current config and post the initial config rather than
	// erroring out (which would leave the enclave stuck unconfigured forever).
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	nodeP2PIds := [][32]byte{
		{0x07, 0x08, 0x09},
		{0x0a, 0x0b, 0x0c},
	}
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: nodeP2PIds,
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/publicKeys", r.URL.Path)
		http.Error(w, "enclave config not set", http.StatusServiceUnavailable)
	}))
	defer publicKeysServer.Close()

	configUpdateReceived := false
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/config", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		var configReq types.ConfigRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&configReq))
		var config types.EnclaveConfig
		require.NoError(t, json.Unmarshal(configReq.Config, &config))

		// The initial config carries the DON signers, requiredF, and the tracker's
		// seeded initial T / master public key.
		assert.Len(t, config.Signers, 2)
		assert.Equal(t, uint32(1), config.F)
		assert.Equal(t, uint32(3), config.T)
		assert.Equal(t, []byte("initial-public-key"), config.MasterPublicKey)

		configUpdateReceived = true
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"status": "success"}))
	}))
	defer configServer.Close()

	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()

	ct := &configTracker{
		initialT:               3,
		initialMasterPublicKey: []byte("initial-public-key"),
	}
	configSet, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, configPort)

	assert.NoError(t, err)
	assert.True(t, configSet, "Config should be reported as set after bootstrapping an unconfigured enclave")
	assert.True(t, configUpdateReceived, "Initial config should have been posted")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_ConfigAlreadySet(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	donID := uint32(123)
	mockRegistry.On("GetDON", mock.Anything, donID).Return(
		capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
			NodeP2PIds: [][32]byte{{0x01}, {0x02}},
			F:          1,
		}, nil,
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PublicKeyPath:
			http.Error(w, "enclave config not set", http.StatusServiceUnavailable)
		case types.SetConfigPath:
			w.WriteHeader(http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	ct := &configTracker{initialT: 1, initialMasterPublicKey: []byte("test-public-key")}
	configSet, err := ct.checkUpdates(context.Background(), createTestLogger(t), mockRegistry, donID, serverURL.Port(), serverURL.Port())

	require.NoError(t, err)
	assert.True(t, configSet)
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_GetDONError(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	mockRegistry.On("GetDON", mock.Anything, donID).Return(
		capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{},
		assert.AnError,
	)

	ct := &configTracker{}
	_, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, "8080", "8081")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get DON")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_DonFZeroError(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: [][32]byte{{0x01, 0x02, 0x03}},
		F:          0,
	}
	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	ct := &configTracker{}
	_, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, "8080", "8081")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DON F value is 0")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_EnclaveConfigFetchError(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: [][32]byte{{0x01, 0x02, 0x03}},
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Use invalid port to cause connection error
	ct := &configTracker{}
	_, err := ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, "99999", "unused")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch enclave config")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_InvalidJSONResponse(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: [][32]byte{{0x01, 0x02, 0x03}},
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Setup test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte("invalid json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	hostPort := serverURL.Port()

	ct := &configTracker{}
	_, err = ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, "8999")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal enclave response")
	mockRegistry.AssertExpectations(t)
}

func TestCheckUpdates_ConfigUpdateError(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	donID := uint32(123)

	nodeP2PIds := [][32]byte{{0x07, 0x08, 0x09}}
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: nodeP2PIds,
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, donID).Return(donInfo, nil)

	// Setup public keys server
	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers:         [][]byte{{0x01, 0x02, 0x03}}, // Different from DON
				MasterPublicKey: []byte("test-public-key"),
				T:               1,
				F:               0,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer publicKeysServer.Close()

	// Setup config server that returns error
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("Internal Server Error"))
		require.NoError(t, err)
	}))
	defer configServer.Close()

	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()

	ct := &configTracker{}
	_, err = ct.checkUpdates(context.Background(), lggr, mockRegistry, donID, hostPort, configPort)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update enclave config")
	mockRegistry.AssertExpectations(t)
}

func TestConfigTracker_StartStop(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)

	// Mock successful DON fetch for the initial check
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: [][32]byte{{0x01, 0x02, 0x03}},
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, uint32(123)).Return(donInfo, nil).Maybe()

	// Setup test server
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers:         [][]byte{toBytes32([]byte{0x01, 0x02, 0x03})},
				MasterPublicKey: []byte("test-public-key"),
				T:               1,
				F:               1,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	hostPort := serverURL.Port()
	tval := uint32(1)
	masterPublicKey := []byte("test-public-key")

	tracker := NewConfigTracker(mockRegistry, lggr, 123, hostPort, "8999", time.Hour, tval, masterPublicKey, false)

	// Test that we can create the tracker and it can perform initial checks
	assert.NotNil(t, tracker)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracker.Start(ctx)
	}()

	require.Eventually(t, func() bool { return callCount.Load() == 1 }, time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Tracker did not stop after cancellation")
	}
	mockRegistry.AssertExpectations(t)
}

func TestConfigTracker_ContinuesPollingAfterConfigSet(t *testing.T) {
	mockRegistry := &MockCapabilitiesRegistry{}
	lggr := createTestLogger(t)
	refreshInterval := 20 * time.Millisecond

	var callCount atomic.Int32
	var configUpdateCount atomic.Int32

	// Mock DON data that will cause an update on the first check
	donInfo := capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo{
		NodeP2PIds: [][32]byte{{0x01, 0x02, 0x03}},
		F:          1,
	}
	mockRegistry.On("GetDON", mock.Anything, uint32(123)).Return(donInfo, nil).Maybe()

	publicKeysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		assert.Equal(t, "/publicKeys", r.URL.Path)
		if call == 2 {
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}

		response := types.PublicKeyResponse{
			Config: types.EnclaveConfig{
				Signers:         [][]byte{{0x07, 0x08, 0x09}},
				MasterPublicKey: []byte("test-public-key"),
				T:               1,
				F:               0,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer publicKeysServer.Close()

	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configUpdateCount.Add(1)
		assert.Equal(t, "/config", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		var configReq types.ConfigRequest
		err := json.NewDecoder(r.Body).Decode(&configReq)
		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		require.NoError(t, err)
	}))
	defer configServer.Close()

	publicKeysURL, err := url.Parse(publicKeysServer.URL)
	require.NoError(t, err)
	hostPort := publicKeysURL.Port()

	configURL, err := url.Parse(configServer.URL)
	require.NoError(t, err)
	configPort := configURL.Port()
	tval := uint32(1)
	masterPublicKey := []byte("test-public-key")

	tracker := NewConfigTracker(mockRegistry, lggr, 123, hostPort, configPort, refreshInterval, tval, masterPublicKey, false)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracker.Start(ctx)
	}()

	require.Eventually(t, func() bool {
		return callCount.Load() >= 4 && configUpdateCount.Load() >= 3
	}, time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Tracker did not stop after cancellation")
	}
	mockRegistry.AssertExpectations(t)
}

type MockCapabilitiesRegistry struct {
	mock.Mock
}

func (m *MockCapabilitiesRegistry) GetDON(opts *bind.CallOpts, donID uint32) (capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo, error) {
	args := m.Called(opts, donID)
	return args.Get(0).(capabilities_registry_wrapper_v2.CapabilitiesRegistryDONInfo), args.Error(1)
}

// Helper function to convert short byte slices to 32-byte arrays
func toBytes32(data []byte) []byte {
	result := make([]byte, 32)
	copy(result, data)
	return result
}

func createTestLogger(t *testing.T) logger.Logger {
	lggr, err := logger.New()
	require.NoError(t, err)
	return lggr
}
