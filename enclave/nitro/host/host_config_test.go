package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/fake"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type delayedConfigReader struct {
	io.Reader
	started chan struct{}
	release chan struct{}
}

func (r *delayedConfigReader) Read(p []byte) (int, error) {
	if r.started != nil {
		close(r.started)
		r.started = nil
		<-r.release
	}
	return r.Reader.Read(p)
}

func TestPublicKeysConfigHydration(t *testing.T) {
	config := types.EnclaveConfig{
		Signers:         [][]byte{bytes.Repeat([]byte{1}, ed25519.PublicKeySize)},
		MasterPublicKey: []byte("master-key"), T: 1, F: 0,
	}
	validBody := " \n" + string(util.MustMarshal(t, types.PublicKeyResponse{
		Config: config, Attestation: []byte("attested-bytes"),
	})) + "\n"
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		initial types.EnclaveConfig
		want    types.EnclaveConfig
	}{
		{name: "recovers complete config including valid zero F", status: 200, body: validBody, want: config},
		{name: "replaces stale config of the same signers", status: 200, body: validBody, initial: types.EnclaveConfig{Signers: config.Signers, MasterPublicKey: []byte("master-key"), T: 7, F: 3}, want: config},
		{name: "unconfigured enclave", status: 503, body: "enclave config not set\n"},
		{name: "non-success with config", status: 500, body: validBody},
		{name: "malformed JSON", status: 200, body: "{"},
		{name: "trailing garbage", status: 200, body: validBody + "garbage"},
		{name: "missing config", status: 200, body: `{}`},
		{name: "zero config", status: 200, body: `{"config":{}}`},
		{name: "missing signers", status: 200, body: `{"config":{"t":1,"f":1,"masterPublicKey":"YQ=="}}`},
		{name: "missing master key", status: 200, body: `{"config":{"t":1,"f":1,"signers":["YQ=="]}}`},
		{name: "missing T", status: 200, body: `{"config":{"f":1,"signers":["YQ=="],"masterPublicKey":"YQ=="}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &mockRoundTripper{response: &http.Response{
				StatusCode: tc.status,
				Header:     http.Header{"Content-Type": {"application/json"}, "X-Enclave": {"unchanged"}},
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}}
			host := NewHostServer(t.Context(), &http.Client{Transport: transport})
			t.Cleanup(host.cancel)
			setTestConfig(t, host, tc.initial)
			w := httptest.NewRecorder()
			host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys?requestID=deadbeef&don=wf_shard-1", nil))
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, tc.body, w.Body.String())
			assert.Equal(t, "unchanged", w.Header().Get("X-Enclave"))
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Equal(t, "deadbeef", transport.requests[0].URL.Query().Get("requestID"))
			assert.Equal(t, "wf_shard-1", transport.requests[0].URL.Query().Get("don"))
			assert.Equal(t, tc.want, hostConfig(t, host))
		})
	}
}

func TestPublicKeysResponseBodyLimit(t *testing.T) {
	config := types.EnclaveConfig{Signers: [][]byte{[]byte("signer")}, MasterPublicKey: []byte("master"), T: 7, F: 3}
	configBody := string(util.MustMarshal(t, types.PublicKeyResponse{Config: config}))
	limitBody := configBody + strings.Repeat(" ", int(types.MaxEnclaveResponseBodyBytes)-len(configBody))
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		initial    types.EnclaveConfig
		wantStatus int
	}{
		{name: "exactly at limit", status: 200, body: limitBody, wantStatus: 200},
		{name: "one byte over limit", status: 200, body: limitBody + " ", wantStatus: 502},
		{name: "existing mirror", status: 200, body: limitBody + " ", initial: config, wantStatus: 502},
		{name: "unsuccessful enclave response", status: 503, body: limitBody + " ", wantStatus: 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := NewHostServer(t.Context(), &http.Client{Transport: &mockRoundTripper{response: &http.Response{
				StatusCode: tc.status,
				Header: http.Header{
					"Content-Type": {"application/json"}, "Content-Length": {strconv.Itoa(len(tc.body))}, "X-Enclave": {"unchanged"},
				},
				Body: io.NopCloser(strings.NewReader(tc.body)),
			}}})
			t.Cleanup(host.cancel)
			setTestConfig(t, host, tc.initial)
			w := httptest.NewRecorder()
			host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
			require.Equal(t, tc.wantStatus, w.Code)
			if tc.wantStatus == http.StatusOK {
				assert.True(t, tc.body == w.Body.String(), "response bytes must be unchanged")
				assert.Equal(t, strconv.Itoa(len(tc.body)), w.Header().Get("Content-Length"))
				assert.Equal(t, "unchanged", w.Header().Get("X-Enclave"))
				assert.Equal(t, config, hostConfig(t, host))
			} else {
				assert.Equal(t, "enclave publicKeys response exceeds size limit\n", w.Body.String())
				assert.Empty(t, w.Header().Get("Content-Length"))
				assert.Empty(t, w.Header().Get("X-Enclave"))
				assert.Equal(t, tc.initial, hostConfig(t, host))
			}
		})
	}
}

func TestPublicKeysHydrationDoesNotOverwriteConcurrentConfig(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			oldConfig := types.EnclaveConfig{Signers: [][]byte{[]byte("old")}, MasterPublicKey: []byte("master"), T: 7, F: 3}
			newConfig := oldConfig.Copy()
			newConfig.Signers = [][]byte{[]byte("new")}
			oldBody := util.MustMarshal(t, types.PublicKeyResponse{Config: oldConfig})
			started, release := make(chan struct{}), make(chan struct{})
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body []byte
				if r.Method == http.MethodGet {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(&delayedConfigReader{
						Reader: bytes.NewReader(oldBody), started: started, release: release,
					})}, nil
				} else {
					body, _ = json.Marshal(types.UpdateConfigResponse{Config: newConfig, Applied: true})
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})
			host := NewHostServer(t.Context(), &http.Client{Transport: transport})
			t.Cleanup(host.cancel)
			w, done := httptest.NewRecorder(), make(chan struct{})
			go func() {
				host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
				close(done)
			}()
			waitForTestSignal(t, started, "GET snapshot")
			update := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/config", strings.NewReader("{}"))
			if method == http.MethodPost {
				host.handleSetConfig(update, r)
			} else {
				host.handleUpdateConfig(update, r)
			}
			close(release)
			waitForTestSignal(t, done, "delayed GET")
			require.Equal(t, http.StatusOK, update.Code)
			assert.Equal(t, oldBody, w.Body.Bytes())
			got, ok := host.configs.lookup(newConfig.Signers[0])
			require.True(t, ok)
			assert.Equal(t, newConfig, got)
		})
	}
}

type configRecoveryApp struct{}

func (configRecoveryApp) Execute(_ [32]byte, _ string, input []byte, _ map[string][]byte, _ types.Emitter, _ types.ExecutionAuth) ([]byte, *types.ExecuteError) {
	return input, nil
}

func TestHostRestartRecoversConfigFromConfiguredEnclave(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	keys := keychain.NewBoxKeychain(logger, nil, nil, nil)
	t.Cleanup(keys.StopKeyRotation)
	_, err := keys.CreateKeyPair()
	require.NoError(t, err)
	enclave := server.NewEnclaveServer(configRecoveryApp{}, &fake.FakeAttestor{}, logger, keys,
		signatureverifier.NewEd25519SignatureVerifier(), nil, nil, types.EnclaveConfig{}, false)
	postCount := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/config" {
			postCount++
		}
		w := httptest.NewRecorder()
		enclave.Handler().ServeHTTP(w, r)
		return w.Result(), nil
	})}
	config := types.EnclaveConfig{MasterPublicKey: []byte("master-key"), T: 7, F: 1}
	privateKeys := make([]ed25519.PrivateKey, quorumThreshold(config.F))
	for i := range privateKeys {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		config.Signers = append(config.Signers, pub)
		privateKeys[i] = priv
	}
	configBody := util.MustMarshal(t, types.ConfigRequest{Config: util.MustMarshal(t, config)}) //nolint:staticcheck // legacy request
	initialHost := NewHostServer(t.Context(), client)
	t.Cleanup(initialHost.cancel)
	w := httptest.NewRecorder()
	initialHost.handleSetConfig(w, httptest.NewRequest(http.MethodPost, "/config", bytes.NewReader(configBody)))
	require.Equal(t, http.StatusOK, w.Code)

	host := NewHostServer(t.Context(), client)
	t.Cleanup(host.cancel)
	request := types.ComputeRequest{RequestID: sha256.Sum256([]byte(t.Name())), AppID: "test", Version: "1.0.0", PublicData: []byte("output")}
	w = httptest.NewRecorder()
	host.handleExecute(w, signedExecuteRequest(t, request, privateKeys[0]))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	w = httptest.NewRecorder()
	host.handleSetConfig(w, httptest.NewRequest(http.MethodPost, "/config", bytes.NewReader(configBody)))
	require.Equal(t, http.StatusConflict, w.Code)
	require.Zero(t, host.configs.len())

	w = httptest.NewRecorder()
	host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var publicKeys types.PublicKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &publicKeys))
	require.Equal(t, config, hostConfig(t, host))
	require.NotEmpty(t, publicKeys.PublicKeys)
	request.EnclaveEphemeralPublicKey = publicKeys.PublicKeys[0]

	responses := make([]*httptest.ResponseRecorder, len(privateKeys))
	done := make([]chan struct{}, len(privateKeys))
	for i, privateKey := range privateKeys {
		responses[i], done[i] = httptest.NewRecorder(), make(chan struct{})
		req := signedExecuteRequest(t, request, privateKey)
		go func() {
			host.handleExecute(responses[i], req)
			close(done[i])
		}()
	}
	for i := range done {
		waitForTestSignal(t, done[i], "execution after host recovery")
		require.Equal(t, http.StatusOK, responses[i].Code, responses[i].Body.String())
		var response types.ExecuteResponse
		require.NoError(t, json.Unmarshal(responses[i].Body.Bytes(), &response))
		assert.Equal(t, request.PublicData, response.Output)
	}
	assert.Equal(t, 2, postCount, "recovery must not POST another configuration")
}

func TestPublicKeysHydrationReadError(t *testing.T) {
	reader, writer := io.Pipe()
	body := util.MustMarshal(t, types.PublicKeyResponse{Config: types.EnclaveConfig{
		Signers: [][]byte{[]byte("signer")}, MasterPublicKey: []byte("master"), T: 7, F: 3,
	}})
	go func() {
		_, _ = writer.Write(body)
		_ = writer.CloseWithError(io.ErrUnexpectedEOF)
	}()
	host := NewHostServer(context.Background(), &http.Client{Transport: &mockRoundTripper{response: &http.Response{
		StatusCode: http.StatusOK, Body: reader,
	}}})
	t.Cleanup(host.cancel)
	w := httptest.NewRecorder()
	host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
	assert.Zero(t, host.configs.len())
	require.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, "failed to read enclave publicKeys response\n", w.Body.String())
}

// setTestConfig sets the host's config mirror to config.
func setTestConfig(t *testing.T, host *hostServer, config types.EnclaveConfig) {
	t.Helper()
	host.configs = &configMirror{}
	if !config.IsZero() {
		host.configs.insert(config)
	}
}

// hostConfig returns the host's only config, or a zero config if it has none.
func hostConfig(t *testing.T, host *hostServer) types.EnclaveConfig {
	t.Helper()
	host.configMutex.RLock()
	defer host.configMutex.RUnlock()
	require.LessOrEqual(t, host.configs.len(), 1)
	if host.configs.len() == 0 {
		return types.EnclaveConfig{}
	}
	return host.configs.configs[0]
}

// testEnclave runs a real enclave server behind an in-memory transport.
type testEnclave struct {
	client *http.Client
	posts  atomic.Int32
}

func newTestEnclave(t *testing.T) *testEnclave {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	keys := keychain.NewBoxKeychain(logger, nil, nil, nil)
	t.Cleanup(keys.StopKeyRotation)
	_, err := keys.CreateKeyPair()
	require.NoError(t, err)
	enclave := server.NewEnclaveServer(configRecoveryApp{}, &fake.FakeAttestor{}, logger, keys,
		signatureverifier.NewEd25519SignatureVerifier(), nil, nil, types.EnclaveConfig{}, false)
	te := &testEnclave{}
	te.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == types.SetConfigPath {
			te.posts.Add(1)
		}
		w := httptest.NewRecorder()
		enclave.Handler().ServeHTTP(w, r)
		return w.Result(), nil
	})}
	return te
}

type testDON struct {
	config types.EnclaveConfig
	keys   []ed25519.PrivateKey
}

func newTestDON(t *testing.T, n int, f uint32) testDON {
	t.Helper()
	don := testDON{config: types.EnclaveConfig{MasterPublicKey: []byte("master-key"), T: 7, F: f}}
	for range n {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		don.config.Signers = append(don.config.Signers, pub)
		don.keys = append(don.keys, priv)
	}
	return don
}

// postConfigs sets configs by DON name; the legacy DON name alone sends a legacy request.
func postConfigs(t *testing.T, host *hostServer, configs map[string]types.EnclaveConfig) int {
	t.Helper()
	req := types.ConfigRequest{Configs: configs}
	if legacy, ok := configs[""]; ok && len(configs) == 1 {
		req = types.ConfigRequest{Config: util.MustMarshal(t, legacy)} //nolint:staticcheck // exercises the legacy field
	}
	w := httptest.NewRecorder()
	host.handleSetConfig(w, httptest.NewRequest(http.MethodPost, types.SetConfigPath, bytes.NewReader(util.MustMarshal(t, req))))
	return w.Code
}

func ephemeralKey(t *testing.T, host *hostServer, don string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys?don="+don, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var publicKeys types.PublicKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &publicKeys))
	require.NotEmpty(t, publicKeys.PublicKeys)
	return publicKeys.PublicKeys[0]
}

// executeQuorum sends request signed by each key concurrently and returns the responses.
func executeQuorum(t *testing.T, host *hostServer, request types.ComputeRequest, keys []ed25519.PrivateKey) []*httptest.ResponseRecorder {
	t.Helper()
	responses := make([]*httptest.ResponseRecorder, len(keys))
	done := make([]chan struct{}, len(keys))
	for i, key := range keys {
		responses[i], done[i] = httptest.NewRecorder(), make(chan struct{})
		req := signedExecuteRequest(t, request, key)
		go func() {
			host.handleExecute(responses[i], req)
			close(done[i])
		}()
	}
	for i := range done {
		waitForTestSignal(t, done[i], "execution")
	}
	return responses
}

func TestHostExecutesUnderSignersDON(t *testing.T) {
	enclave := newTestEnclave(t)
	shard0 := newTestDON(t, 3, 1)
	shard1 := newTestDON(t, 1, 0)
	host := NewHostServer(t.Context(), enclave.client)
	t.Cleanup(host.cancel)
	require.Equal(t, http.StatusOK, postConfigs(t, host, map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}))
	assert.Equal(t, 2, host.configs.len(), "the host learns all configs from the POST response")

	for _, tc := range []struct {
		don  string
		keys []ed25519.PrivateKey
		want types.EnclaveConfig
	}{
		{don: "wf", keys: shard0.keys[:quorumThreshold(1)], want: shard0.config},
		{don: "wf_shard-1", keys: shard1.keys, want: shard1.config},
	} {
		t.Run(tc.don, func(t *testing.T) {
			request := types.ComputeRequest{RequestID: sha256.Sum256([]byte(t.Name())), AppID: "test", Version: "1.0.0", PublicData: []byte("output")}
			request.EnclaveEphemeralPublicKey = ephemeralKey(t, host, tc.don)
			for _, w := range executeQuorum(t, host, request, tc.keys) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				var response types.ExecuteResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				assert.Equal(t, []byte("output"), response.Output)
				assert.Equal(t, tc.want, response.Config)
			}
		})
	}
}

func TestHostRejectsBatchAcrossDONs(t *testing.T) {
	enclave := newTestEnclave(t)
	donA := newTestDON(t, 2, 1)
	donB := newTestDON(t, 2, 1)
	host := NewHostServer(t.Context(), enclave.client)
	t.Cleanup(host.cancel)
	require.Equal(t, http.StatusOK, postConfigs(t, host, map[string]types.EnclaveConfig{"a": donA.config, "b": donB.config}))

	request := types.ComputeRequest{RequestID: sha256.Sum256([]byte(t.Name())), AppID: "test", Version: "1.0.0", EnclaveEphemeralPublicKey: ephemeralKey(t, host, "a")}
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan struct{})
	firstReq := signedExecuteRequest(t, request, donA.keys[0]).WithContext(ctx)
	go func() {
		host.handleExecute(httptest.NewRecorder(), firstReq)
		close(first)
	}()
	require.Eventually(t, func() bool {
		_, ok := host.pendingRequestsCache.Get(request.Hash())
		return ok
	}, 2*time.Second, 10*time.Millisecond)

	w := httptest.NewRecorder()
	host.handleExecute(w, signedExecuteRequest(t, request, donB.keys[0]))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "batched for another DON")
	cancel()
	waitForTestSignal(t, first, "first request")
}

func TestPublicKeysTeachesHostEachDON(t *testing.T) {
	enclave := newTestEnclave(t)
	shard0, shard1 := newTestDON(t, 1, 0), newTestDON(t, 1, 0)
	writer := NewHostServer(t.Context(), enclave.client)
	t.Cleanup(writer.cancel)
	require.Equal(t, http.StatusOK, postConfigs(t, writer, map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}))

	// A host that missed the POST learns each DON from that DON's publicKeys call.
	host := NewHostServer(t.Context(), enclave.client)
	t.Cleanup(host.cancel)
	request := types.ComputeRequest{RequestID: sha256.Sum256([]byte(t.Name())), AppID: "test", Version: "1.0.0"}
	w := httptest.NewRecorder()
	host.handleExecute(w, signedExecuteRequest(t, request, shard1.keys[0]))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	request.EnclaveEphemeralPublicKey = ephemeralKey(t, host, "wf_shard-1")
	w = httptest.NewRecorder()
	host.handleExecute(w, signedExecuteRequest(t, request, shard1.keys[0]))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	_, ok := host.configs.lookup(shard0.config.Signers[0])
	assert.False(t, ok, "shard 0 is not learned until its nodes ask")
	ephemeralKey(t, host, "wf")
	_, ok = host.configs.lookup(shard0.config.Signers[0])
	assert.True(t, ok)
}

func TestConfigMirrorInsertDropsOverlapping(t *testing.T) {
	a := newTestDON(t, 2, 0).config
	b := newTestDON(t, 1, 0).config
	m := &configMirror{}
	m.insert(a)
	m.insert(b)
	require.Equal(t, 2, m.len())

	// A node moves from a to b: the new b drops the stale a.
	moved := b.Copy()
	moved.Signers = append(moved.Signers, a.Signers[1])
	m.insert(moved)
	assert.Equal(t, 1, m.len())
	got, ok := m.lookup(a.Signers[1])
	require.True(t, ok)
	assert.Equal(t, moved, got)
	_, ok = m.lookup(a.Signers[0])
	assert.False(t, ok, "re-learned on a's next publicKeys")
}
