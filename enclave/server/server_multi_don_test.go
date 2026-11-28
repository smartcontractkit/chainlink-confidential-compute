package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

type authRecordingApp struct {
	auth      types.ExecutionAuth
	defaultFn func(types.EnclaveConfig)
}

func (a *authRecordingApp) Execute(_ [32]byte, _ string, _ []byte, _ map[string][]byte, _ types.Emitter, auth types.ExecutionAuth) ([]byte, *types.ExecuteError) {
	a.auth = auth
	return []byte("ok"), nil
}

func (a *authRecordingApp) OnConfigUpdate(cfg types.EnclaveConfig) {
	if a.defaultFn != nil {
		a.defaultFn(cfg)
	}
}

type multiDONServer struct {
	t       *testing.T
	server  *enclaveServer
	handler http.Handler
	app     *authRecordingApp
	keys    keychain.Keychain
}

func newMultiDONServer(t *testing.T) *multiDONServer {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	kc := keychain.NewBoxKeychain(logger, nil, nil, nil)
	t.Cleanup(kc.StopKeyRotation)
	_, err := kc.CreateKeyPair()
	require.NoError(t, err)
	app := &authRecordingApp{}
	s := NewEnclaveServer(app, &mockAttestor{}, logger, kc, signatureverifier.NewEd25519SignatureVerifier(),
		&mockCombiner{}, emitter.NewNoOpEmitter(), types.EnclaveConfig{}, false)
	return &multiDONServer{t: t, server: s, handler: s.Handler(), app: app, keys: kc}
}

func (m *multiDONServer) do(method, path string, body any) *httptest.ResponseRecorder {
	m.t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(util.MustMarshal(m.t, body))
	}
	w := httptest.NewRecorder()
	m.handler.ServeHTTP(w, httptest.NewRequest(method, path, r))
	return w
}

func (m *multiDONServer) post(configs map[string]types.EnclaveConfig) *httptest.ResponseRecorder {
	m.t.Helper()
	return m.do(http.MethodPost, types.SetConfigPath, types.ConfigRequest{Configs: configs})
}

func (m *multiDONServer) postLegacy(cfg types.EnclaveConfig) *httptest.ResponseRecorder {
	m.t.Helper()
	return m.do(http.MethodPost, types.SetConfigPath, legacyConfigRequest(util.MustMarshal(m.t, cfg)))
}

func (m *multiDONServer) publicKeys(query string) (int, types.PublicKeyResponse) {
	m.t.Helper()
	w := m.do(http.MethodGet, types.PublicKeyPath+query, nil)
	var resp types.PublicKeyResponse
	if w.Code == http.StatusOK {
		require.NoError(m.t, json.Unmarshal(w.Body.Bytes(), &resp))
	}
	return w.Code, resp
}

func (m *multiDONServer) configs() map[string]types.EnclaveConfig {
	m.t.Helper()
	m.server.configLock.Lock()
	defer m.server.configLock.Unlock()
	return m.server.configs.Snapshot()
}

func (m *multiDONServer) execute(signers ...ed25519.PrivateKey) *httptest.ResponseRecorder {
	m.t.Helper()
	pairs, err := m.keys.GetKeyPairs()
	require.NoError(m.t, err)
	req := types.ComputeRequest{
		RequestID:                 sha256.Sum256([]byte(m.t.Name())),
		AppID:                     "test",
		Version:                   "1.0.0",
		EnclaveEphemeralPublicKey: pairs[0].Public(),
	}
	hash := req.Hash()
	payload := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	var batch []types.SignedComputeRequest
	for _, k := range signers {
		batch = append(batch, types.SignedComputeRequest{ComputeRequest: req, Signature: ed25519.Sign(k, payload)})
	}
	return m.do(http.MethodPost, types.ExecutePath, batch)
}

type don struct {
	config types.EnclaveConfig
	keys   []ed25519.PrivateKey
}

func newDON(t *testing.T, n int, f uint32) don {
	t.Helper()
	d := don{config: types.EnclaveConfig{MasterPublicKey: []byte("master"), T: 1, F: f}}
	for range n {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		d.config.Signers = append(d.config.Signers, pub)
		d.keys = append(d.keys, priv)
	}
	return d
}

func vote(t *testing.T, cfg types.EnclaveConfig, priv ed25519.PrivateKey) types.UpdateConfigRequest {
	t.Helper()
	hash := cfg.Hash()
	payload := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputeConfigUpdatePrefix(), hash[:])
	return types.UpdateConfigRequest{Config: util.MustMarshal(t, cfg), Signature: ed25519.Sign(priv, payload)}
}

func TestSetConfig_PerDON(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	shard0, shard1 := newDON(t, 2, 1), newDON(t, 1, 0)
	configs := map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}

	overlap := newDON(t, 1, 0).config
	overlap.Signers = append(overlap.Signers, shard0.config.Signers[0])
	assert.Equal(t, http.StatusBadRequest, m.post(map[string]types.EnclaveConfig{"wf": shard0.config, "other": overlap}).Code, "signers must be disjoint across DONs")
	assert.Equal(t, http.StatusBadRequest, m.post(map[string]types.EnclaveConfig{"": shard0.config}).Code)

	w := m.post(configs)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp types.SetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, configs, resp.Configs)
	assert.Equal(t, "wf", resp.DONName)
	assert.Equal(t, shard0.config, resp.Config, "older clients read the shard-0 config")

	// Configs are set once; adding a DON needs a restart.
	assert.Equal(t, http.StatusConflict, m.post(map[string]types.EnclaveConfig{"wf_shard-2": newDON(t, 1, 0).config}).Code)
	assert.Equal(t, http.StatusConflict, m.postLegacy(newDON(t, 1, 0).config).Code)
	assert.Equal(t, configs, m.configs())
}

func TestSetConfig_PerDONIgnoresLegacyField(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	d := newDON(t, 1, 0)
	req := legacyConfigRequest(util.MustMarshal(t, d.config))
	req.Configs = map[string]types.EnclaveConfig{"wf": d.config}
	require.Equal(t, http.StatusOK, m.do(http.MethodPost, types.SetConfigPath, req).Code)
	assert.Equal(t, map[string]types.EnclaveConfig{"wf": d.config}, m.configs())
}

func TestPublicKeys_PerDON(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	shard0, shard1 := newDON(t, 1, 0), newDON(t, 1, 0)

	code, _ := m.publicKeys("?don=wf")
	assert.Equal(t, http.StatusServiceUnavailable, code)

	legacy := newMultiDONServer(t)
	require.Equal(t, http.StatusOK, legacy.postLegacy(shard0.config).Code)
	_, resp := legacy.publicKeys("?don=wf")
	assert.Equal(t, shard0.config, resp.Config, "the legacy config serves any DON")

	require.Equal(t, http.StatusOK, m.post(map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}).Code)
	_, resp = m.publicKeys("?don=wf_shard-1")
	assert.Equal(t, shard1.config, resp.Config)
	_, resp = m.publicKeys("")
	assert.Equal(t, shard0.config, resp.Config, "older nodes get shard 0")
	code, _ = m.publicKeys("?don=unknown")
	assert.Equal(t, http.StatusServiceUnavailable, code)
}

func TestUpdateConfig_VoteUpdatesSignersDON(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	var notified []types.EnclaveConfig
	m.app.defaultFn = func(cfg types.EnclaveConfig) { notified = append(notified, cfg) }
	shard0, shard1 := newDON(t, 2, 1), newDON(t, 2, 1)
	require.Equal(t, http.StatusOK, m.post(map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}).Code)

	proposed := newDON(t, 3, 1).config
	patch := func(priv ed25519.PrivateKey) (int, types.UpdateConfigResponse) {
		w := m.do(http.MethodPatch, types.SetConfigPath, vote(t, proposed, priv))
		var resp types.UpdateConfigResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	// Votes from different DONs for the same config do not add up.
	code, resp := patch(shard0.keys[0])
	require.Equal(t, http.StatusAccepted, code)
	assert.Equal(t, "wf", resp.DONName)
	code, resp = patch(shard1.keys[0])
	require.Equal(t, http.StatusAccepted, code)
	assert.Equal(t, "wf_shard-1", resp.DONName)
	assert.Equal(t, 1, resp.SignersCollected)

	code, resp = patch(shard1.keys[1])
	require.Equal(t, http.StatusOK, code)
	assert.True(t, resp.Applied)
	assert.Equal(t, "wf_shard-1", resp.DONName)
	assert.Equal(t, map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": proposed}, m.configs())
	assert.Equal(t, shard0.config, notified[len(notified)-1], "the app is notified with the shard-0 config")

	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	code, _ = patch(stranger)
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestUpdateConfig_RejectsOverlapUntilOtherDONReleasesSigner(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	shard0, shard1 := newDON(t, 2, 0), newDON(t, 1, 0)
	require.Equal(t, http.StatusOK, m.post(map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}).Code)

	// Move shard0's second node to shard 1.
	grown := shard1.config.Copy()
	grown.Signers = append(grown.Signers, shard0.config.Signers[1])
	assert.Equal(t, http.StatusBadRequest, m.do(http.MethodPatch, types.SetConfigPath, vote(t, grown, shard1.keys[0])).Code)

	shrunk := shard0.config.Copy()
	shrunk.Signers = shrunk.Signers[:1]
	require.Equal(t, http.StatusOK, m.do(http.MethodPatch, types.SetConfigPath, vote(t, shrunk, shard0.keys[0])).Code)
	require.Equal(t, http.StatusOK, m.do(http.MethodPatch, types.SetConfigPath, vote(t, grown, shard1.keys[0])).Code)
}

func TestUpdateConfig_LegacyConfig(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	d := newDON(t, 1, 0)
	require.Equal(t, http.StatusOK, m.postLegacy(d.config).Code)

	proposed := newDON(t, 1, 0).config
	require.Equal(t, http.StatusOK, m.do(http.MethodPatch, types.SetConfigPath, vote(t, proposed, d.keys[0])).Code)
	assert.Equal(t, map[string]types.EnclaveConfig{"": proposed}, m.configs())
}

func TestHandleExecute_PerDON(t *testing.T) {
	t.Parallel()
	m := newMultiDONServer(t)
	shard0, shard1 := newDON(t, 2, 1), newDON(t, 1, 0)
	require.Equal(t, http.StatusOK, m.post(map[string]types.EnclaveConfig{"wf": shard0.config, "wf_shard-1": shard1.config}).Code)

	t.Run("signers select the config", func(t *testing.T) {
		m.t = t
		w := m.execute(shard1.keys[0])
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp types.ExecuteResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, shard1.config, resp.Config)
		assert.Equal(t, "wf_shard-1", m.app.auth.CapRegDONName)
		assert.Len(t, m.app.auth.SignedRequests, 1)
	})
	t.Run("quorum uses the DON's F", func(t *testing.T) {
		m.t = t
		assert.Equal(t, http.StatusBadRequest, m.execute(shard0.keys[0]).Code)
	})
	t.Run("batch across DONs", func(t *testing.T) {
		m.t = t
		w := m.execute(shard0.keys[0], shard1.keys[0])
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), `signed by DON \"wf_shard-1\"`)
	})
}
