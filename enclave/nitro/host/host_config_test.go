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
	"testing"

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
		{name: "preserves existing mirror", status: 200, body: validBody, initial: types.EnclaveConfig{T: 7, F: 3}, want: types.EnclaveConfig{T: 7, F: 3}},
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
			host.config = tc.initial
			w := httptest.NewRecorder()
			host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys?requestID=deadbeef", nil))
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, tc.body, w.Body.String())
			assert.Equal(t, "unchanged", w.Header().Get("X-Enclave"))
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Equal(t, "deadbeef", transport.requests[0].URL.Query().Get("requestID"))
			assert.Equal(t, tc.want, host.config)
		})
	}
}

func TestMaybeRecoverConfigSkipsConfiguredHost(t *testing.T) {
	host := NewHostServer(t.Context(), &http.Client{})
	t.Cleanup(host.cancel)
	config := types.EnclaveConfig{Signers: [][]byte{[]byte("signer")}, MasterPublicKey: []byte("master"), T: 7, F: 3}
	host.config = config.Copy()

	require.NoError(t, host.maybeRecoverConfig([]byte("{")), "an initialized mirror must skip decoding")
	assert.Equal(t, config, host.config)
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
			host.config = tc.initial
			w := httptest.NewRecorder()
			host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
			require.Equal(t, tc.wantStatus, w.Code)
			if tc.wantStatus == http.StatusOK {
				assert.True(t, tc.body == w.Body.String(), "response bytes must be unchanged")
				assert.Equal(t, strconv.Itoa(len(tc.body)), w.Header().Get("Content-Length"))
				assert.Equal(t, "unchanged", w.Header().Get("X-Enclave"))
				assert.Equal(t, config, host.config)
			} else {
				assert.Equal(t, "enclave publicKeys response exceeds size limit\n", w.Body.String())
				assert.Empty(t, w.Header().Get("Content-Length"))
				assert.Empty(t, w.Header().Get("X-Enclave"))
				assert.Equal(t, tc.initial, host.config)
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
			assert.Equal(t, newConfig, host.config)
		})
	}
}

type configRecoveryApp struct{}

func (configRecoveryApp) Execute(_ [32]byte, _ string, input []byte, _ map[string][]byte, _ types.Emitter, _ ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
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
	configBody := util.MustMarshal(t, types.ConfigRequest{Config: util.MustMarshal(t, config)})
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
	require.True(t, host.config.IsZero())

	w = httptest.NewRecorder()
	host.handleGetPublicKeys(w, httptest.NewRequest(http.MethodGet, "/publicKeys", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var publicKeys types.PublicKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &publicKeys))
	require.Equal(t, config, host.config)
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
	assert.True(t, host.config.IsZero())
	require.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, "failed to read enclave publicKeys response\n", w.Body.String())
}
