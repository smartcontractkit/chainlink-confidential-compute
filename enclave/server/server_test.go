package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"

	enclavetypes "github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAttestor struct{}

func (m *mockAttestor) CreateAttestation(data []byte) ([]byte, error) {
	return []byte("mock-attestation"), nil
}

// countingAttestor records how many times CreateAttestation is invoked so tests
// can assert the /publicKeys attestation cache dedupes NSM work.
type countingAttestor struct {
	mu    sync.Mutex
	calls int
}

func (m *countingAttestor) CreateAttestation(data []byte) ([]byte, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return []byte("mock-attestation"), nil
}

func (m *countingAttestor) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type mockCombiner struct{}

var _ combiner.Combiner = (*mockCombiner)(nil)

func (m *mockCombiner) AggregateShares(ciphertext []byte, shares [][]byte, masterPubkeyBytes []byte, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("not enough valid shares to decrypt (%d/%d)", len(shares), threshold)
	}
	return ciphertext, nil
}

func (m *mockCombiner) VerifyShare(ciphertext []byte, masterPublicKey []byte, share []byte) error {
	return fmt.Errorf("not implemented")
}

// mockEnclaveApp is a mock implementation of types.EnclaveApp for server testing
type mockEnclaveApp struct {
	executeFunc func([32]byte, string, []byte, map[string][]byte, types.Emitter) ([]byte, *types.ExecuteError)
}

var _ types.EnclaveApp = (*mockEnclaveApp)(nil)

// newMockEnclaveApp creates a new mock app with default behavior
func newMockEnclaveApp() *mockEnclaveApp {
	return &mockEnclaveApp{
		executeFunc: func(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter) ([]byte, *types.ExecuteError) {
			// Default mock behavior: return a simple success response
			return []byte(`[{"statusCode":200,"body":"mock response","headers":{"Content-Type":"application/json"}}]`), nil
		},
	}
}

func (m *mockEnclaveApp) Execute(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter, _ ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
	return m.executeFunc(requestID, appID, inputData, secretsMap, emitter)
}

// encryptShare encrypts a byte slice with a recipient's public key
func encryptShare(data []byte, publicKeyBytes []byte) ([]byte, error) {
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid public key length")
	}

	var publicKey [32]byte
	copy(publicKey[:], publicKeyBytes)

	return box.SealAnonymous(nil, data, &publicKey, nil)
}

func setupTestServerWithMockApp(t *testing.T, mockApp types.EnclaveApp) string {
	verifier := signatureverifier.NewEd25519SignatureVerifier()

	// Create a test server with TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	logger := log.New(new(bytes.Buffer), "", 0)
	serverInstance := NewEnclaveServer(
		mockApp,
		&mockAttestor{},
		logger,
		keychain.NewBoxKeychain(logger, nil, nil, nil),
		verifier,
		&mockCombiner{},
		emitter.NewNoOpEmitter(),
		types.EnclaveConfig{},
		false,
	)

	go func() {
		// Start the server in a goroutine
		err := serverInstance.Start(listener)
		if err != nil {
			t.Logf("server exited with error: %v", err)
		}
	}()

	// Get the server URL
	serverURL := "http://" + listener.Addr().String()

	// Poll until the server is accepting connections and has generated a public key.
	client := &http.Client{Timeout: 100 * time.Millisecond}
	maxRetries := 50
	for i := 0; i < maxRetries; i++ {
		pubKeyResp, err := client.Get(serverURL + "/publicKeys")
		if err == nil {
			// A 503 means the server is accepting connections but has no config
			// yet. That is the expected pre-configuration state; tests set config
			// themselves after startup, so treat it as "server is up".
			if pubKeyResp.StatusCode == http.StatusServiceUnavailable {
				util.SafeClose(pubKeyResp)
				return serverURL
			}
			if pubKeyResp.StatusCode == http.StatusOK {
				var pkResponseBody types.PublicKeyResponse
				err = json.NewDecoder(pubKeyResp.Body).Decode(&pkResponseBody)
				util.SafeClose(pubKeyResp)
				require.NoError(t, err)
				if len(pkResponseBody.PublicKeys) > 0 {
					return serverURL
				}
			} else {
				util.SafeClose(pubKeyResp)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("server failed to start within the expected time")
	return ""
}

// assertErrorResponse verifies the JSON error response format from WriteErrorResponse
// and returns the parsed metrics map for further assertions.
func assertErrorResponse(t *testing.T, resp *http.Response, expectedError string) map[string]any {
	t.Helper()
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body struct {
		Error   string         `json:"error"`
		Metrics map[string]any `json:"metrics"`
	}
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.Contains(t, body.Error, expectedError)
	require.NotNil(t, body.Metrics, "error response should contain metrics")
	return body.Metrics
}

func TestGetPublicKeysAttestationCache(t *testing.T) {
	t.Parallel()

	logger := log.New(new(bytes.Buffer), "", 0)
	kc := keychain.NewBoxKeychain(logger, nil, nil, nil)
	defer kc.StopKeyRotation()
	attestor := &countingAttestor{}

	s := NewEnclaveServer(
		newMockEnclaveApp(),
		attestor,
		logger,
		kc,
		signatureverifier.NewEd25519SignatureVerifier(),
		&mockCombiner{},
		emitter.NewNoOpEmitter(),
		// The handler serves 503 until a non-zero config is set.
		types.EnclaveConfig{MasterPublicKey: []byte("master-public-key"), T: 1},
		false,
	)

	// Wait for the keychain's initial keypair to be generated.
	require.Eventually(t, func() bool {
		keys, err := kc.GetKeyPairs()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 5*time.Millisecond)

	getPublicKeys := func() {
		req := httptest.NewRequest(http.MethodGet, "/publicKeys", nil)
		rr := httptest.NewRecorder()
		s.handleGetPublicKeys(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var resp types.PublicKeyResponse
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		require.NotEmpty(t, resp.Attestation)
	}

	// Repeated requests over identical attested content should hit the NSM once.
	for i := 0; i < 5; i++ {
		getPublicKeys()
	}
	assert.Equal(t, 1, attestor.Calls(), "attested content is unchanged; NSM should be hit once")

	// Once the cached attestation expires, the next request must re-attest.
	shortTTL := 10 * time.Millisecond
	s.pubKeyAttestations = util.NewCache[[]byte](&shortTTL, nil)
	getPublicKeys()
	require.Equal(t, 2, attestor.Calls())
	require.Eventually(t, func() bool {
		getPublicKeys()
		return attestor.Calls() > 2
	}, time.Second, 5*time.Millisecond, "expired cache entry should force re-attestation")
}

func TestSetConfig(t *testing.T) {
	t.Parallel()

	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	// Generate a random configuration to set
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	config := types.EnclaveConfig{
		Signers: [][]byte{
			pubKey,
		},
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               0,
	}
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	tests := []struct {
		name              string
		method            string
		config            []byte
		pubKey            []byte
		body              string
		expectedStatus    int
		checkConfig       bool
		expectedErrorText string
	}{
		{
			name:              "Invalid HTTP method",
			method:            http.MethodGet,
			expectedStatus:    http.StatusMethodNotAllowed,
			checkConfig:       false,
			expectedErrorText: "Method Not Allowed",
		},
		{
			name:              "Invalid JSON body",
			method:            http.MethodPost,
			body:              "invalid json",
			expectedStatus:    http.StatusBadRequest,
			checkConfig:       false,
			expectedErrorText: "failed to parse config request",
		},
		{
			name:           "Valid config",
			method:         http.MethodPost,
			config:         configBytes,
			pubKey:         pubKey,
			expectedStatus: http.StatusOK,
			checkConfig:    true,
		},
		{
			name:              "Config already set",
			method:            http.MethodPost,
			config:            configBytes,
			pubKey:            pubKey,
			expectedStatus:    http.StatusConflict,
			checkConfig:       false,
			expectedErrorText: "config has already been set",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			var err error

			if tt.body != "" {
				req, err = http.NewRequest(tt.method, serverURL+"/config", bytes.NewReader([]byte(tt.body)))
				require.NoError(t, err)
			} else if tt.config != nil {
				reqBody := types.ConfigRequest{
					Config: tt.config,
				}
				body, err := json.Marshal(reqBody)
				require.NoError(t, err)
				req, err = http.NewRequest(tt.method, serverURL+"/config", bytes.NewReader(body))
				require.NoError(t, err)
			} else {
				req, err = http.NewRequest(tt.method, serverURL+"/config", nil)
				require.NoError(t, err)
			}

			if tt.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer util.SafeClose(resp)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus == http.StatusOK {
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var responseBody types.SetConfigResponse
				err = json.NewDecoder(resp.Body).Decode(&responseBody)
				require.NoError(t, err)
				assert.Equal(t, []byte("mock-attestation"), responseBody.Attestation)

				if tt.checkConfig {
					assert.Equal(t, config, responseBody.Config)
				}
			} else if tt.expectedErrorText != "" {
				responseBody, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(responseBody), tt.expectedErrorText)
			}

			// If this was a successful config update, verify it was applied by making a request to /publicKeys.
			if tt.checkConfig {
				// Make a request to /publicKey to check if the config was updated
				pkReq, err := http.NewRequest(http.MethodGet, serverURL+"/publicKeys", nil)
				require.NoError(t, err)

				pkResp, err := client.Do(pkReq)
				require.NoError(t, err)
				defer util.SafeClose(pkResp)

				var pkResponseBody types.PublicKeyResponse
				err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
				require.NoError(t, err)

				assert.Equal(t, config, pkResponseBody.Config)
			}
		})
	}
}

// setInitialConfig POSTs an initial config to a freshly started server.
func setInitialConfig(t *testing.T, serverURL string, config types.EnclaveConfig) {
	t.Helper()
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)
	body, err := json.Marshal(types.ConfigRequest{Config: configBytes})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// patchConfigVote submits a config-update vote signed by priv.
func patchConfigVote(t *testing.T, serverURL string, proposed types.EnclaveConfig, priv ed25519.PrivateKey) (*http.Response, types.UpdateConfigResponse) {
	t.Helper()
	configBytes, err := json.Marshal(proposed)
	require.NoError(t, err)
	hash := proposed.Hash()
	prefixed := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputeConfigUpdatePrefix(), hash[:])
	sig := ed25519.Sign(priv, prefixed)
	body, err := json.Marshal(types.UpdateConfigRequest{Config: configBytes, Signature: sig})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPatch, serverURL+"/config", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var out types.UpdateConfigResponse
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	}
	return resp, out
}

func TestUpdateConfig(t *testing.T) {
	t.Parallel()

	s1Pub, s1Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s2Pub, s2Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s3Pub, s3Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	outsiderPub, outsiderPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Initial config: 3 signers, F=1 -> quorum to update is F+1 = 2.
	initialConfig := types.EnclaveConfig{
		Signers:         [][]byte{s1Pub, s2Pub, s3Pub},
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               1,
	}

	// Proposed config: rotate s3 out for a new signer, keep MasterPublicKey and T.
	proposedConfig := types.EnclaveConfig{
		Signers:         [][]byte{s1Pub, s2Pub, outsiderPub},
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               1,
	}

	t.Run("rejects update before config is initialized", func(t *testing.T) {
		t.Parallel()
		serverURL := setupTestServerWithMockApp(t, newMockEnclaveApp())
		resp, _ := patchConfigVote(t, serverURL, proposedConfig, s1Priv)
		defer util.SafeClose(resp)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("rejects vote from a non-signer", func(t *testing.T) {
		t.Parallel()
		serverURL := setupTestServerWithMockApp(t, newMockEnclaveApp())
		setInitialConfig(t, serverURL, initialConfig)
		resp, _ := patchConfigVote(t, serverURL, proposedConfig, outsiderPriv)
		defer util.SafeClose(resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("accumulates votes and applies at quorum", func(t *testing.T) {
		t.Parallel()
		serverURL := setupTestServerWithMockApp(t, newMockEnclaveApp())
		setInitialConfig(t, serverURL, initialConfig)

		// First vote: recorded but below quorum (1 of 2).
		resp1, out1 := patchConfigVote(t, serverURL, proposedConfig, s1Priv)
		defer util.SafeClose(resp1)
		assert.Equal(t, http.StatusAccepted, resp1.StatusCode)
		assert.False(t, out1.Applied)
		assert.Equal(t, 1, out1.SignersCollected)
		assert.Equal(t, 2, out1.SignersRequired)

		// Duplicate vote from same signer does not advance the count.
		resp1b, out1b := patchConfigVote(t, serverURL, proposedConfig, s1Priv)
		defer util.SafeClose(resp1b)
		assert.Equal(t, http.StatusAccepted, resp1b.StatusCode)
		assert.Equal(t, 1, out1b.SignersCollected)

		// Second distinct vote reaches quorum and applies.
		resp2, out2 := patchConfigVote(t, serverURL, proposedConfig, s2Priv)
		defer util.SafeClose(resp2)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
		assert.True(t, out2.Applied)
		assert.Equal(t, 2, out2.SignersCollected)
		assert.Equal(t, proposedConfig, out2.Config)
		assert.Equal(t, []byte("mock-attestation"), out2.Attestation)

		// /publicKeys now reflects the new config.
		pkResp, err := http.DefaultClient.Get(serverURL + "/publicKeys")
		require.NoError(t, err)
		defer util.SafeClose(pkResp)
		var pk types.PublicKeyResponse
		require.NoError(t, json.NewDecoder(pkResp.Body).Decode(&pk))
		assert.Equal(t, proposedConfig, pk.Config)

		// The rotated-out signer (s3) can no longer authorize updates; a vote it
		// casts for yet another config is rejected.
		nextConfig := proposedConfig
		nextConfig.MasterPublicKey = []byte("another-key")
		resp3, _ := patchConfigVote(t, serverURL, nextConfig, s3Priv)
		defer util.SafeClose(resp3)
		assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	})

	t.Run("drops update matching current config without quorum", func(t *testing.T) {
		t.Parallel()
		serverURL := setupTestServerWithMockApp(t, newMockEnclaveApp())
		setInitialConfig(t, serverURL, initialConfig)

		// A single vote for the config already in effect applies immediately without
		// needing F+1 votes, and leaves the config unchanged.
		resp, out := patchConfigVote(t, serverURL, initialConfig, s1Priv)
		defer util.SafeClose(resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, out.Applied)
		assert.Equal(t, initialConfig, out.Config)
		assert.Equal(t, []byte("mock-attestation"), out.Attestation)

		pkResp, err := http.DefaultClient.Get(serverURL + "/publicKeys")
		require.NoError(t, err)
		defer util.SafeClose(pkResp)
		var pk types.PublicKeyResponse
		require.NoError(t, json.NewDecoder(pkResp.Body).Decode(&pk))
		assert.Equal(t, initialConfig, pk.Config)
	})
}

func TestPublicKey(t *testing.T) {
	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	testConfig := types.EnclaveConfig{
		MasterPublicKey: []byte{},
		Signers: [][]byte{
			pubKey,
		},
	}
	configBytes, err := json.Marshal(testConfig)
	require.NoError(t, err)

	configReq := types.ConfigRequest{
		Config: configBytes,
	}
	configBody, err := json.Marshal(configReq)
	require.NoError(t, err)

	configHttpReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
	require.NoError(t, err)
	configHttpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	configResp, err := client.Do(configHttpReq)
	require.NoError(t, err)
	util.SafeClose(configResp)
	require.Equal(t, http.StatusOK, configResp.StatusCode)

	req, err := http.NewRequest(http.MethodGet, serverURL+"/publicKeys?requestHash=test-hash", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var responseBody types.PublicKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	require.NoError(t, err)

	assert.NotEmpty(t, responseBody.PublicKeys)
	assert.Equal(t, []byte("mock-attestation"), responseBody.Attestation)

	assert.Equal(t, testConfig, responseBody.Config)

	req, err = http.NewRequest(http.MethodGet, serverURL+"/publicKeys", nil)
	require.NoError(t, err)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	req, err = http.NewRequest(http.MethodPost, serverURL+"/publicKeys", nil)
	require.NoError(t, err)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	errorBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(errorBody), "method not allowed")
}

func TestHandleMemory(t *testing.T) {
	t.Parallel()

	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, serverURL+types.MemoryPath, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var mem types.MemoryEstimateResponse
	err = json.NewDecoder(resp.Body).Decode(&mem)
	require.NoError(t, err)

	// The value comes from the Go runtime; we can't assert an exact number, but a
	// running process always has some memory mapped.
	assert.Positive(t, mem.UsedMB)

	// Non-GET methods are rejected.
	req, err = http.NewRequest(http.MethodPost, serverURL+types.MemoryPath, nil)
	require.NoError(t, err)
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// configureTestServer POSTs a minimal non-zero config so the server will serve
// /publicKeys. Tests that only need keys served (not the unconfigured 503
// behavior) call this right after startup.
func configureTestServer(t *testing.T, serverURL string) {
	t.Helper()
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	configBytes, err := json.Marshal(types.EnclaveConfig{
		Signers:         [][]byte{pubKey},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               0,
	})
	require.NoError(t, err)
	body, err := json.Marshal(types.ConfigRequest{Config: configBytes})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	defer util.SafeClose(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPublicKey_WithRequestID(t *testing.T) {
	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)
	configureTestServer(t, serverURL)
	client := &http.Client{}

	t.Run("returns single pinned key for valid requestID", func(t *testing.T) {
		requestID := fmt.Sprintf("%064x", 1) // valid 32-byte hex
		resp, err := client.Get(serverURL + "/publicKeys?requestID=" + requestID)
		require.NoError(t, err)
		defer util.SafeClose(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body types.PublicKeyResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Len(t, body.PublicKeys, 1, "should return exactly one pinned keypair")
		assert.Len(t, body.CreationTimes, 1)
		assert.Len(t, body.TTLs, 1)
	})

	t.Run("same requestID returns same key", func(t *testing.T) {
		requestID := fmt.Sprintf("%064x", 2)

		resp1, err := client.Get(serverURL + "/publicKeys?requestID=" + requestID)
		require.NoError(t, err)
		defer util.SafeClose(resp1)
		require.Equal(t, http.StatusOK, resp1.StatusCode)
		var body1 types.PublicKeyResponse
		err = json.NewDecoder(resp1.Body).Decode(&body1)
		require.NoError(t, err)

		resp2, err := client.Get(serverURL + "/publicKeys?requestID=" + requestID)
		require.NoError(t, err)
		defer util.SafeClose(resp2)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		var body2 types.PublicKeyResponse
		err = json.NewDecoder(resp2.Body).Decode(&body2)
		require.NoError(t, err)

		assert.Equal(t, body1.PublicKeys[0], body2.PublicKeys[0],
			"same requestID should return the same pinned key")
	})

	t.Run("invalid requestID returns 400", func(t *testing.T) {
		resp, err := client.Get(serverURL + "/publicKeys?requestID=not-hex")
		require.NoError(t, err)
		defer util.SafeClose(resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("too short requestID returns 400", func(t *testing.T) {
		resp, err := client.Get(serverURL + "/publicKeys?requestID=aabb")
		require.NoError(t, err)
		defer util.SafeClose(resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("base64-encoded requestID works for backwards compatibility", func(t *testing.T) {
		// Old clients use base64 encoding (util.EncodeToString) instead of hex.
		var rawID [32]byte
		rawID[0] = 0xBB
		b64RequestID := base64.StdEncoding.EncodeToString(rawID[:])

		resp, err := client.Get(serverURL + "/publicKeys?requestID=" + b64RequestID)
		require.NoError(t, err)
		defer util.SafeClose(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body types.PublicKeyResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Len(t, body.PublicKeys, 1, "should return exactly one pinned keypair for base64 requestID")
	})

	t.Run("no requestID returns all keys", func(t *testing.T) {
		resp, err := client.Get(serverURL + "/publicKeys")
		require.NoError(t, err)
		defer util.SafeClose(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body types.PublicKeyResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(body.PublicKeys), 1,
			"without requestID should return all available keys")
	})
}

func TestHandleExecute_ConcurrencyPushback(t *testing.T) {
	verifier := signatureverifier.NewEd25519SignatureVerifier()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	logger := log.New(new(bytes.Buffer), "", 0)
	s := NewEnclaveServer(
		newMockEnclaveApp(),
		&mockAttestor{},
		logger,
		keychain.NewBoxKeychain(logger, nil, nil, nil),
		verifier,
		&mockCombiner{},
		emitter.NewNoOpEmitter(),
		types.EnclaveConfig{},
		false,
		WithMaxConcurrentExecutions(2),
	)
	go func() { _ = s.Start(listener) }()
	serverURL := "http://" + listener.Addr().String()

	post := func() *http.Response {
		var resp *http.Response
		require.Eventually(t, func() bool {
			req, _ := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader([]byte("[]")))
			r, e := http.DefaultClient.Do(req)
			if e != nil {
				return false
			}
			resp = r
			return true
		}, 2*time.Second, 20*time.Millisecond)
		return resp
	}

	// Saturate the execution semaphore; the next execute must be rejected fast
	// with 429 (before any body read / signature verification).
	require.True(t, s.execSem.TryAcquire(2))
	resp := post()
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	require.Contains(t, string(body), "at capacity")

	// Free the slots; requests are admitted again (they fail later validation,
	// but are no longer rejected at the concurrency gate).
	s.execSem.Release(2)
	resp2 := post()
	require.NoError(t, resp2.Body.Close())
	require.NotEqual(t, http.StatusTooManyRequests, resp2.StatusCode)
}

func TestHandleExecute_QuorumValidation(t *testing.T) {
	t.Parallel()

	// Generate multiple authorized signers
	signer1Pub, signer1Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer2Pub, signer2Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer3Pub, signer3Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name           string
		configF        uint32
		signers        []ed25519.PublicKey
		requestSigners []ed25519.PrivateKey
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "F=0, 1 signer required (0+1=1), 1 provided - should pass",
			configF:        0,
			signers:        []ed25519.PublicKey{signer1Pub},
			requestSigners: []ed25519.PrivateKey{signer1Priv},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "F=1, 2 signers required (1+1=2), 3 provided - should pass",
			configF:        1,
			signers:        []ed25519.PublicKey{signer1Pub, signer2Pub, signer3Pub},
			requestSigners: []ed25519.PrivateKey{signer1Priv, signer2Priv, signer3Priv},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "F=1, 2 signers required (1+1=2), 2 provided - should pass",
			configF:        1,
			signers:        []ed25519.PublicKey{signer1Pub, signer2Pub, signer3Pub},
			requestSigners: []ed25519.PrivateKey{signer1Priv, signer2Priv},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "F=1, 2 signers required (1+1=2), 1 provided - should fail",
			configF:        1,
			signers:        []ed25519.PublicKey{signer1Pub, signer2Pub, signer3Pub},
			requestSigners: []ed25519.PrivateKey{signer1Priv},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "not enough requests by unique signers to reach quorum, got 1, need 2",
		},
		{
			name:    "F=0, duplicate signatures from same signer - should pass (only need 1 unique signer)",
			configF: 0,
			signers: []ed25519.PublicKey{signer1Pub, signer2Pub},
			// Duplicate signer1Priv - counts as 1 unique signer, and we need 0+1 = 1
			requestSigners: []ed25519.PrivateKey{signer1Priv, signer1Priv},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Each subtest gets its own server since config can only be set once.
			mockApp := newMockEnclaveApp()
			serverURL := setupTestServerWithMockApp(t, mockApp)

			// Set up config with the specified F value and signers
			signerPubKeys := make([][]byte, len(tt.signers))
			for i, pub := range tt.signers {
				signerPubKeys[i] = pub
			}

			testConfig := types.EnclaveConfig{
				Signers:         signerPubKeys,
				MasterPublicKey: []byte("master-public-key"),
				T:               1,
				F:               tt.configF,
			}
			configBytes, err := json.Marshal(testConfig)
			require.NoError(t, err)

			configReq := types.ConfigRequest{
				Config: configBytes,
			}
			configBody, err := json.Marshal(configReq)
			require.NoError(t, err)

			configHttpReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
			require.NoError(t, err)
			configHttpReq.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			configResp, err := client.Do(configHttpReq)
			require.NoError(t, err)
			util.SafeClose(configResp)
			require.Equal(t, http.StatusOK, configResp.StatusCode)

			// Fetch the server's public key
			pkReq, err := http.NewRequest(http.MethodGet, serverURL+"/publicKeys", nil)
			require.NoError(t, err)
			pkResp, err := client.Do(pkReq)
			require.NoError(t, err)
			defer util.SafeClose(pkResp)

			var pkResponseBody types.PublicKeyResponse
			err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
			require.NoError(t, err)
			serverPublicKey := pkResponseBody.PublicKeys[0]

			// Create request
			request := &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"test": true}`},
			}

			publicDataBytes, err := proto.Marshal(request)
			require.NoError(t, err)

			// Create mock encrypted shares
			cipherTexts := [][]byte{[]byte("encrypted-secret")}
			cipherTextNames := []string{"secret1"}
			shares := make([][][]byte, 1)
			shares[0] = make([][]byte, testConfig.T)
			for j := range shares[0] {
				rawShare := []byte(fmt.Sprintf("share-%d", j))
				encryptedShare, err := encryptShare(rawShare, serverPublicKey)
				require.NoError(t, err)
				shares[0][j] = encryptedShare
			}

			computeReq := types.ComputeRequest{
				RequestID:                    sha256.Sum256([]byte("test-quorum-" + tt.name)),
				ApplicationRequestID:         "test-quorum-" + tt.name,
				PublicData:                   publicDataBytes,
				Ciphertexts:                  cipherTexts,
				CiphertextNames:              cipherTextNames,
				MasterPublicKey:              testConfig.MasterPublicKey,
				EnclaveEphemeralPublicKey:    serverPublicKey,
				EncryptedDecryptionKeyShares: shares,
				AppID:                        "test-app",
				Version:                      "1.0.0",
			}

			// Create signed requests from each specified signer
			signedReqs := make([]types.SignedComputeRequest, len(tt.requestSigners))
			hash := computeReq.Hash()
			prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])

			for i, privKey := range tt.requestSigners {
				signature := ed25519.Sign(privKey, prefixedHash[:])
				signedReqs[i] = types.SignedComputeRequest{
					ComputeRequest: computeReq,
					Signature:      signature,
				}
			}

			bodyBytes, err := json.Marshal(signedReqs)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader(bodyBytes))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer util.SafeClose(resp)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedError != "" {
				assertErrorResponse(t, resp, tt.expectedError)
			} else if tt.expectedStatus == http.StatusOK {
				var responseBody types.ExecuteResponse
				err = json.NewDecoder(resp.Body).Decode(&responseBody)
				require.NoError(t, err)
				assert.NotEmpty(t, responseBody.Output)
				assert.NotEmpty(t, responseBody.RequestID)
				assert.Equal(t, computeReq.ApplicationRequestID, responseBody.ApplicationRequestID)
			}
		})
	}
}

func TestHandleExecute_ServerConcerns(t *testing.T) {
	// Test server-level concerns for the /requests endpoint using mock app
	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	// Generate an authorized signer private key that we'll use to sign requests.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Generate an initial config that can be verified.
	testConfig := types.EnclaveConfig{
		Signers: [][]byte{
			pubKey,
		},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               0,
	}
	configBytes, err := json.Marshal(testConfig)
	require.NoError(t, err)

	configReq := types.ConfigRequest{
		Config: configBytes,
	}
	configBody, err := json.Marshal(configReq)
	require.NoError(t, err)
	configHttpReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
	require.NoError(t, err)
	configHttpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	configResp, err := client.Do(configHttpReq)
	require.NoError(t, err)
	util.SafeClose(configResp)
	require.Equal(t, http.StatusOK, configResp.StatusCode)

	// Fetch the server's public key to encrypt shares
	pkReq, err := http.NewRequest(http.MethodGet, serverURL+"/publicKeys", nil)
	require.NoError(t, err)
	pkResp, err := client.Do(pkReq)
	require.NoError(t, err)
	defer util.SafeClose(pkResp)
	var pkResponseBody types.PublicKeyResponse
	err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
	require.NoError(t, err)
	serverPublicKey := pkResponseBody.PublicKeys[0]

	cipherTexts := [][]byte{
		[]byte("encrypted-secret1"),
		[]byte("encrypted-secret2"),
	}
	cipherTextNames := []string{
		"secret1", "secret2",
	}

	tests := []struct {
		name                         string
		request                      *enclavetypes.Request
		executeRequestMethodOverride string
		executeRequestOverride       interface{}
		mockAppBehavior              func(*mockEnclaveApp)
		expectedStatus               int
		expectedError                string
		cipherTextNames              []string
	}{
		{
			name: "successful execution with mock app",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"test": true}`},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "mismatched number of ciphertexts and names",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"test": true}`},
			},
			expectedStatus:  http.StatusBadRequest,
			expectedError:   "number of ciphertexts (2) does not match number of ciphertext names (1)",
			cipherTextNames: []string{"onlyone"}, // Mismatch with expected 2 ciphertexts
		},
		{
			name: "app returns error",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
			},
			mockAppBehavior: func(m *mockEnclaveApp) {
				m.executeFunc = func(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter) ([]byte, *types.ExecuteError) {
					return nil, &types.ExecuteError{
						Error: "mock app error",
						Code:  http.StatusBadRequest,
					}
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "mock app error",
		},
		{
			name:                         "invalid http method for execute endpoint",
			executeRequestMethodOverride: http.MethodGet,
			expectedStatus:               http.StatusMethodNotAllowed,
			expectedError:                "method not allowed",
		},
		{
			name:                   "invalid json body for execute endpoint",
			executeRequestOverride: "invalid json",
			expectedStatus:         http.StatusBadRequest,
			expectedError:          "invalid json",
		},
		{
			name:                   "empty request batch",
			executeRequestOverride: []types.SignedComputeRequest{}, // Valid JSON but empty array
			expectedStatus:         http.StatusBadRequest,
			expectedError:          "empty request batch",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Apply mock app behavior if specified
			if tt.mockAppBehavior != nil {
				tt.mockAppBehavior(mockApp)
			}

			var requestBody interface{}
			if tt.request != nil {
				publicDataBytes, err := proto.Marshal(tt.request)
				require.NoError(t, err)

				// Create mock encrypted decryption shares for each ciphertext
				localCipherTextNames := cipherTextNames
				if tt.cipherTextNames != nil {
					localCipherTextNames = tt.cipherTextNames
				}
				shares := make([][][]byte, len(localCipherTextNames))
				for i := range shares {
					shares[i] = make([][]byte, testConfig.T)
					for j := range shares[i] {
						rawShare := []byte(fmt.Sprintf("share-%d-%d", i, j))
						encryptedShare, err := encryptShare(rawShare, serverPublicKey)
						require.NoError(t, err)
						shares[i][j] = encryptedShare
					}
				}

				computeReq := types.ComputeRequest{
					RequestID:                    sha256.Sum256([]byte("test-" + tt.name)),
					PublicData:                   publicDataBytes,
					Ciphertexts:                  cipherTexts,
					CiphertextNames:              localCipherTextNames,
					MasterPublicKey:              testConfig.MasterPublicKey,
					EnclaveEphemeralPublicKey:    serverPublicKey,
					EncryptedDecryptionKeyShares: shares,
					AppID:                        "test-app",
					Version:                      "1.0.0",
				}

				hash := computeReq.Hash()
				prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
				signature := ed25519.Sign(privKey, prefixedHash[:])
				signedReq := types.SignedComputeRequest{
					ComputeRequest: computeReq,
					Signature:      signature,
				}

				requestBody = []types.SignedComputeRequest{signedReq}
			}

			if tt.executeRequestOverride != nil {
				requestBody = tt.executeRequestOverride
			}

			requestMethod := http.MethodPost
			if tt.executeRequestMethodOverride != "" {
				requestMethod = tt.executeRequestMethodOverride
			}

			var req *http.Request
			if requestBody == nil {
				req, err = http.NewRequest(requestMethod, serverURL+"/requests", nil)
				require.NoError(t, err)
			} else if s, ok := requestBody.(string); ok {
				req, err = http.NewRequest(requestMethod, serverURL+"/requests", bytes.NewReader([]byte(s)))
				require.NoError(t, err)
			} else {
				bodyBytes, err := json.Marshal(requestBody)
				require.NoError(t, err)
				req, err = http.NewRequest(requestMethod, serverURL+"/requests", bytes.NewReader(bodyBytes))
				require.NoError(t, err)
			}

			if requestMethod == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer util.SafeClose(resp)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedError != "" {
				metrics := assertErrorResponse(t, resp, tt.expectedError)
				// Verify request_started metric is always present, even in error responses.
				_, ok := metrics["request_started"]
				assert.True(t, ok, "error response should contain request_started metric")

				// Error responses must carry the total request duration tagged
				// outcome=error so error latency is recorded.
				requestCompleted, ok := metrics["request_completed"].(map[string]any)
				require.True(t, ok, "error response should contain request_completed metric")
				assert.Equal(t, "error", requestCompleted["outcome"])
				assert.Equal(t, "execute", requestCompleted["endpoint"])
				assert.EqualValues(t, tt.expectedStatus, requestCompleted["status_code"])
				duration, ok := requestCompleted["duration_seconds"].(float64)
				require.True(t, ok, "duration_seconds should be a float64")
				assert.GreaterOrEqual(t, duration, float64(0))
			} else {
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var responseBody types.ExecuteResponse
				respBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				err = json.Unmarshal(respBytes, &responseBody)
				require.NoError(t, err)

				// Verify basic structure without testing app logic
				assert.NotEmpty(t, responseBody.Output)
				assert.NotEmpty(t, responseBody.RequestID)

				// Verify metrics are present and contain expected content
				require.NotNil(t, responseBody.Metrics, "response should contain metrics")

				// Verify request_started content
				requestStarted, ok := responseBody.Metrics["request_started"].(map[string]any)
				require.True(t, ok, "request_started should be a map")
				assert.Equal(t, "execute", requestStarted["endpoint"])

				// Verify signature_verification_completed content
				sigVerify, ok := responseBody.Metrics["signature_verification_completed"].(map[string]any)
				require.True(t, ok, "signature_verification_completed should be a map")
				assert.NotNil(t, sigVerify["duration_seconds"])
				assert.Equal(t, float64(1), sigVerify["num_signatures"])

				// Verify shares_combining_completed content
				sharesCombine, ok := responseBody.Metrics["shares_combining_completed"].(map[string]any)
				require.True(t, ok, "shares_combining_completed should be a map")
				assert.NotNil(t, sharesCombine["duration_seconds"])

				// Verify request_completed content
				requestCompleted, ok := responseBody.Metrics["request_completed"].(map[string]any)
				require.True(t, ok, "request_completed should be a map")
				assert.Equal(t, "execute", requestCompleted["endpoint"])
				// Success path is tagged outcome=success so it shares the
				// request_completed metric with the error path.
				assert.Equal(t, "success", requestCompleted["outcome"])
				duration, ok := requestCompleted["duration_seconds"].(float64)
				require.True(t, ok, "duration_seconds should be a float64")
				assert.GreaterOrEqual(t, duration, float64(0))
			}
		})
	}
}

func TestHandleExecute_ShareFallback(t *testing.T) {
	t.Parallel()

	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	// Generate two authorized signers.
	signer1Pub, signer1Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer2Pub, signer2Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testConfig := types.EnclaveConfig{
		Signers:         [][]byte{signer1Pub, signer2Pub},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               0,
	}
	configBytes, err := json.Marshal(testConfig)
	require.NoError(t, err)
	configReq := types.ConfigRequest{Config: configBytes}
	configBody, err := json.Marshal(configReq)
	require.NoError(t, err)

	client := &http.Client{}
	configHttpReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
	require.NoError(t, err)
	configHttpReq.Header.Set("Content-Type", "application/json")
	configResp, err := client.Do(configHttpReq)
	require.NoError(t, err)
	util.SafeClose(configResp)
	require.Equal(t, http.StatusOK, configResp.StatusCode)

	// Fetch the server's public key.
	pkResp, err := client.Get(serverURL + "/publicKeys")
	require.NoError(t, err)
	defer util.SafeClose(pkResp)
	var pkResponseBody types.PublicKeyResponse
	err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
	require.NoError(t, err)
	serverPublicKey := pkResponseBody.PublicKeys[0]

	cipherTexts := [][]byte{[]byte("encrypted-secret")}
	cipherTextNames := []string{"secret1"}

	// Build valid shares for signer2.
	goodShares := make([][][]byte, 1)
	goodShares[0] = make([][]byte, testConfig.T)
	for j := range goodShares[0] {
		rawShare := []byte(fmt.Sprintf("share-%d", j))
		enc, err := encryptShare(rawShare, serverPublicKey)
		require.NoError(t, err)
		goodShares[0][j] = enc
	}

	// Build garbage shares for signer1 (not properly encrypted).
	badShares := make([][][]byte, 1)
	badShares[0] = [][]byte{[]byte("garbage")}

	computeReqBase := types.ComputeRequest{
		RequestID:                 sha256.Sum256([]byte("test-share-fallback")),
		PublicData:                []byte("{}"),
		Ciphertexts:               cipherTexts,
		CiphertextNames:           cipherTextNames,
		MasterPublicKey:           testConfig.MasterPublicKey,
		EnclaveEphemeralPublicKey: serverPublicKey,
		AppID:                     "test-app",
		Version:                   "1.0.0",
	}

	// Request from signer1 carries bad shares.
	req1 := computeReqBase
	req1.EncryptedDecryptionKeyShares = badShares
	hash := req1.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	sig1 := ed25519.Sign(signer1Priv, prefixedHash[:])
	signedReq1 := types.SignedComputeRequest{ComputeRequest: req1, Signature: sig1}

	// Request from signer2 carries good shares.
	req2 := computeReqBase
	req2.EncryptedDecryptionKeyShares = goodShares
	hash2 := req2.Hash()
	prefixedHash2 := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash2[:])
	sig2 := ed25519.Sign(signer2Priv, prefixedHash2[:])
	signedReq2 := types.SignedComputeRequest{ComputeRequest: req2, Signature: sig2}

	// Send bad-shares node first so the server must fall back to the second node.
	bodyBytes, err := json.Marshal([]types.SignedComputeRequest{signedReq1, signedReq2})
	require.NoError(t, err)

	httpReq, err := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "server should fall back to the second node's shares")

	var responseBody types.ExecuteResponse
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	require.NoError(t, err)
	assert.NotEmpty(t, responseBody.Output)
}

// A node whose EncryptedDecryptionKeyShares slice is shorter than the batch's
// Ciphertexts must not panic the enclave (the shares field is not covered by
// ComputeRequest.Hash()). The server should skip that node and fall back to a
// node that carries the correct number of share sets.
func TestHandleExecute_ShortSharesNoPanic(t *testing.T) {
	t.Parallel()

	mockApp := newMockEnclaveApp()
	serverURL := setupTestServerWithMockApp(t, mockApp)

	signer1Pub, signer1Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer2Pub, signer2Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testConfig := types.EnclaveConfig{
		Signers:         [][]byte{signer1Pub, signer2Pub},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               0,
	}
	configBytes, err := json.Marshal(testConfig)
	require.NoError(t, err)
	configReq := types.ConfigRequest{Config: configBytes}
	configBody, err := json.Marshal(configReq)
	require.NoError(t, err)

	client := &http.Client{}
	configHttpReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
	require.NoError(t, err)
	configHttpReq.Header.Set("Content-Type", "application/json")
	configResp, err := client.Do(configHttpReq)
	require.NoError(t, err)
	util.SafeClose(configResp)
	require.Equal(t, http.StatusOK, configResp.StatusCode)

	pkResp, err := client.Get(serverURL + "/publicKeys")
	require.NoError(t, err)
	defer util.SafeClose(pkResp)
	var pkResponseBody types.PublicKeyResponse
	err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
	require.NoError(t, err)
	serverPublicKey := pkResponseBody.PublicKeys[0]

	cipherTexts := [][]byte{[]byte("encrypted-secret")}
	cipherTextNames := []string{"secret1"}

	// Valid shares for signer2 (one set, matching the single ciphertext).
	goodShares := make([][][]byte, 1)
	goodShares[0] = make([][]byte, testConfig.T)
	for j := range goodShares[0] {
		rawShare := []byte(fmt.Sprintf("share-%d", j))
		enc, err := encryptShare(rawShare, serverPublicKey)
		require.NoError(t, err)
		goodShares[0][j] = enc
	}

	computeReqBase := types.ComputeRequest{
		RequestID:                 sha256.Sum256([]byte("test-short-shares")),
		PublicData:                []byte("{}"),
		Ciphertexts:               cipherTexts,
		CiphertextNames:           cipherTextNames,
		MasterPublicKey:           testConfig.MasterPublicKey,
		EnclaveEphemeralPublicKey: serverPublicKey,
		AppID:                     "test-app",
		Version:                   "1.0.0",
	}

	// signer1 carries an empty shares slice: shorter than Ciphertexts. This is
	// the payload that would index out of range without the length guard.
	req1 := computeReqBase
	req1.EncryptedDecryptionKeyShares = [][][]byte{}
	hash := req1.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	sig1 := ed25519.Sign(signer1Priv, prefixedHash[:])
	signedReq1 := types.SignedComputeRequest{ComputeRequest: req1, Signature: sig1}

	// signer2 carries good shares. Note: because the shares field is not part of
	// Hash(), both requests share the same hash and pass batch validation.
	req2 := computeReqBase
	req2.EncryptedDecryptionKeyShares = goodShares
	hash2 := req2.Hash()
	prefixedHash2 := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash2[:])
	sig2 := ed25519.Sign(signer2Priv, prefixedHash2[:])
	signedReq2 := types.SignedComputeRequest{ComputeRequest: req2, Signature: sig2}

	// Send the short-shares node first so the server must skip it, not panic.
	bodyBytes, err := json.Marshal([]types.SignedComputeRequest{signedReq1, signedReq2})
	require.NoError(t, err)

	httpReq, err := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer util.SafeClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "server should skip the short-shares node and fall back to the valid one")

	var responseBody types.ExecuteResponse
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	require.NoError(t, err)
	assert.NotEmpty(t, responseBody.Output)
}

func TestHandleExecute_ReplayProtection(t *testing.T) {
	t.Parallel()

	var (
		execCount int
		execMu    sync.Mutex
	)

	mockApp := newMockEnclaveApp()
	mockApp.executeFunc = func(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter) ([]byte, *types.ExecuteError) {
		execMu.Lock()
		execCount++
		execMu.Unlock()
		return []byte(`[{"statusCode":200,"body":"ok"}]`), nil
	}

	serverURL := setupTestServerWithMockApp(t, mockApp)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testConfig := types.EnclaveConfig{
		Signers:         [][]byte{pubKey},
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               0,
	}
	configBytes, err := json.Marshal(testConfig)
	require.NoError(t, err)

	configReq := types.ConfigRequest{Config: configBytes}
	configBody, err := json.Marshal(configReq)
	require.NoError(t, err)

	client := &http.Client{}
	configHTTPReq, err := http.NewRequest(http.MethodPost, serverURL+"/config", bytes.NewReader(configBody))
	require.NoError(t, err)
	configHTTPReq.Header.Set("Content-Type", "application/json")

	configResp, err := client.Do(configHTTPReq)
	require.NoError(t, err)
	util.SafeClose(configResp)
	require.Equal(t, http.StatusOK, configResp.StatusCode)

	pkResp, err := client.Get(serverURL + "/publicKeys")
	require.NoError(t, err)
	defer util.SafeClose(pkResp)

	var pkResponseBody types.PublicKeyResponse
	err = json.NewDecoder(pkResp.Body).Decode(&pkResponseBody)
	require.NoError(t, err)
	serverPublicKey := pkResponseBody.PublicKeys[0]

	request := &enclavetypes.Request{
		Method: http.MethodPost,
		Url:    "https://example.com/api",
		Body:   &enclavetypes.Request_BodyString{BodyString: `{"test": true}`},
	}

	publicDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	shares := make([][][]byte, 1)
	shares[0] = make([][]byte, testConfig.T)
	for i := range shares[0] {
		rawShare := []byte(fmt.Sprintf("share-%d", i))
		encryptedShare, encErr := encryptShare(rawShare, serverPublicKey)
		require.NoError(t, encErr)
		shares[0][i] = encryptedShare
	}

	computeReq := types.ComputeRequest{
		RequestID:                    sha256.Sum256([]byte("test-replay-protection")),
		PublicData:                   publicDataBytes,
		Ciphertexts:                  [][]byte{[]byte("encrypted-secret")},
		CiphertextNames:              []string{"secret1"},
		MasterPublicKey:              testConfig.MasterPublicKey,
		EnclaveEphemeralPublicKey:    serverPublicKey,
		EncryptedDecryptionKeyShares: shares,
		AppID:                        "test-app",
		Version:                      "1.0.0",
	}

	hash := computeReq.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	signature := ed25519.Sign(privKey, prefixedHash[:])

	signedReq := types.SignedComputeRequest{ComputeRequest: computeReq, Signature: signature}
	bodyBytes, err := json.Marshal([]types.SignedComputeRequest{signedReq})
	require.NoError(t, err)

	firstReq, err := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	firstReq.Header.Set("Content-Type", "application/json")

	firstResp, err := client.Do(firstReq)
	require.NoError(t, err)
	defer util.SafeClose(firstResp)
	require.Equal(t, http.StatusOK, firstResp.StatusCode)

	secondReq, err := http.NewRequest(http.MethodPost, serverURL+"/requests", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	secondReq.Header.Set("Content-Type", "application/json")

	secondResp, err := client.Do(secondReq)
	require.NoError(t, err)
	defer util.SafeClose(secondResp)
	require.Equal(t, http.StatusConflict, secondResp.StatusCode)
	assertErrorResponse(t, secondResp, "replay detected")

	execMu.Lock()
	defer execMu.Unlock()
	require.Equal(t, 1, execCount, "replayed request must not execute app twice")
}

// blockingAttestor counts CreateAttestation calls and blocks each one until
// release is closed, letting tests pile up concurrent cache misses.
type blockingAttestor struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
}

func (m *blockingAttestor) CreateAttestation(data []byte) ([]byte, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	<-m.release
	return []byte("mock-attestation"), nil
}

func (m *blockingAttestor) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestGetPublicKeysAttestationSingleflight(t *testing.T) {
	t.Parallel()

	logger := log.New(new(bytes.Buffer), "", 0)
	kc := keychain.NewBoxKeychain(logger, nil, nil, nil)
	defer kc.StopKeyRotation()
	attestor := &blockingAttestor{release: make(chan struct{})}

	s := NewEnclaveServer(
		newMockEnclaveApp(),
		attestor,
		logger,
		kc,
		signatureverifier.NewEd25519SignatureVerifier(),
		&mockCombiner{},
		emitter.NewNoOpEmitter(),
		// The handler serves 503 until a non-zero config is set.
		types.EnclaveConfig{MasterPublicKey: []byte("master-public-key"), T: 1},
		false,
	)

	// Wait for the keychain's initial keypair to be generated.
	require.Eventually(t, func() bool {
		keys, err := kc.GetKeyPairs()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 5*time.Millisecond)

	// Fire concurrent requests over identical attested content while the
	// attestor is blocked, so every request misses the cache.
	const concurrency = 8
	var wg sync.WaitGroup
	codes := make([]int, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/publicKeys", nil)
			rr := httptest.NewRecorder()
			s.handleGetPublicKeys(rr, req)
			codes[i] = rr.Code
		}(i)
	}

	// Once the leader is inside the attestor, let every request through.
	require.Eventually(t, func() bool { return attestor.Calls() == 1 }, 2*time.Second, time.Millisecond)
	close(attestor.release)
	wg.Wait()

	for i, code := range codes {
		require.Equal(t, http.StatusOK, code, "request %d", i)
	}
	assert.Equal(t, 1, attestor.Calls(), "concurrent misses must collapse into one NSM attestation")
}

// erroringAttestor fails the first `failures` CreateAttestation calls, then
// succeeds by echoing the attested data.
type erroringAttestor struct {
	mu       sync.Mutex
	calls    int
	failures int
}

func (m *erroringAttestor) CreateAttestation(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.calls <= m.failures {
		return nil, fmt.Errorf("nsm unavailable")
	}
	return append([]byte("att:"), data...), nil
}

func (m *erroringAttestor) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestAttestPublicKeys(t *testing.T) {
	t.Parallel()

	newServer := func(a attestor.Attestor) *enclaveServer {
		ttl := time.Minute
		return &enclaveServer{
			attestor:           a,
			pubKeyAttestations: util.NewCache[[]byte](&ttl, nil),
		}
	}

	t.Run("caches per content hash", func(t *testing.T) {
		t.Parallel()
		a := &erroringAttestor{}
		s := newServer(a)
		hashA := [32]byte{1}
		hashB := [32]byte{2}

		attA, err := s.attestPublicKeys(hashA)
		require.NoError(t, err)
		assert.Equal(t, append([]byte("att:"), hashA[:]...), attA)

		// Same hash is served from the cache; a different hash re-attests.
		again, err := s.attestPublicKeys(hashA)
		require.NoError(t, err)
		assert.Equal(t, attA, again)
		assert.Equal(t, 1, a.Calls())

		attB, err := s.attestPublicKeys(hashB)
		require.NoError(t, err)
		assert.Equal(t, append([]byte("att:"), hashB[:]...), attB)
		assert.Equal(t, 2, a.Calls())
	})

	t.Run("errors propagate and are not cached", func(t *testing.T) {
		t.Parallel()
		a := &erroringAttestor{failures: 1}
		s := newServer(a)
		hash := [32]byte{3}

		_, err := s.attestPublicKeys(hash)
		require.ErrorContains(t, err, "nsm unavailable")

		// A failure is not cached; the next call retries the attestor.
		att, err := s.attestPublicKeys(hash)
		require.NoError(t, err)
		assert.Equal(t, append([]byte("att:"), hash[:]...), att)
		assert.Equal(t, 2, a.Calls())
	})
}
