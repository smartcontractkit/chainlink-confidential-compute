package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/host/binaryfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

// Settings without storage credentials mean the deployment runs no workflow
// binaries: no provider, and no error.
func TestNewBinaryProvider_NilWithoutStorageSettings(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	t.Cleanup(withBinaryCacheDir(t.TempDir()))
	for name, settings := range map[string]string{
		"empty":           "",
		"whitespace":      "   ",
		"unrelated app":   `{"gatewayUrl":"https://gateway"}`,
		"empty json body": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := newBinaryProvider(settings, lggr)
			require.NoError(t, err, "missing storage settings should disable fetching, not error")
			assert.Nil(t, p)
		})
	}
}

// Storage credentials with no cache directory is a deployment mistake: the
// enclave cannot fetch for itself, so the host must refuse to start rather than
// fail every execution at runtime.
func TestNewBinaryProvider_ErrorsWhenCacheDirMissing(t *testing.T) {
	t.Cleanup(withBinaryCacheDir(""))
	_, err := newBinaryProvider(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443"}`,
		cllogger.Sugared(cllogger.Nop()),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BINARY_CACHE_DIR")
}

func TestNewBinaryProvider_RejectsMalformedSettings(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	t.Cleanup(withBinaryCacheDir(t.TempDir()))

	_, err := newBinaryProvider("not json", lggr)
	require.Error(t, err)

	_, err = newBinaryProvider(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage:443","binaryFetchTimeout":"nope"}`,
		lggr,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binaryFetchTimeout")
	for _, settings := range []string{`{"storageServiceUrl":"storage:443"}`, `{"storageKey":"` + testStorageKeyHex + `"}`} {
		_, err := newBinaryProvider(settings, lggr)
		require.ErrorContains(t, err, "both required")
	}
}

func TestNewBinaryProvider_Enabled(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	t.Cleanup(withBinaryCacheDir(t.TempDir()))
	for value, want := range map[string]time.Duration{
		`"30s"`: 30 * time.Second, `30000000000`: 30 * time.Second,
		`"0s"`: types.DefaultBinaryFetchTimeout, `0`: types.DefaultBinaryFetchTimeout,
		`-1`: types.DefaultBinaryFetchTimeout,
	} {
		t.Run(value, func(t *testing.T) {
			p, err := newBinaryProvider(
				`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443","binaryFetchTimeout":`+value+`}`,
				lggr,
			)
			require.NoError(t, err)
			require.NotNil(t, p)
			t.Cleanup(func() { require.NoError(t, p.Close()) })
			assert.Equal(t, want, p.timeout)
		})
	}
}

// withBinaryCacheDir points the flag at dir and returns a cleanup that restores it.
func withBinaryCacheDir(dir string) func() {
	previous := *binaryCacheDir
	*binaryCacheDir = dir
	return func() { *binaryCacheDir = previous }
}

// A nil provider is the no-storage-credentials case, which startup already
// vetted. It must stay safe to call rather than panicking.
func TestBinaryProvider_NilIsSafe(t *testing.T) {
	var p *binaryProvider
	binary, err := p.binaryFor(t.Context(), nil)
	assert.Nil(t, binary)
	assert.ErrorContains(t, err, "not configured")
	assert.NoError(t, p.Close())
}

// An execution missing the fields needed to fetch is an error naming them,
// rather than a silent "no binary" the enclave has to rediscover.
func TestBinaryProvider_IncompleteExecutionErrors(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	t.Cleanup(withBinaryCacheDir(t.TempDir()))
	p, err := newBinaryProvider(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443"}`,
		lggr,
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })

	for name, tt := range map[string]struct {
		execution *confworkflowtypes.WorkflowExecution
		want      string
	}{
		"no workflow id": {&confworkflowtypes.WorkflowExecution{BinaryUrl: "storage://b", BinaryHash: []byte{1}}, "workflow_id"},
		"no binary url":  {&confworkflowtypes.WorkflowExecution{WorkflowId: "wf", BinaryHash: []byte{1}}, "binary_url"},
		"no hash":        {&confworkflowtypes.WorkflowExecution{WorkflowId: "wf", BinaryUrl: "storage://b"}, "binary_hash"},
	} {
		t.Run(name, func(t *testing.T) {
			binary, err := p.binaryFor(t.Context(), tt.execution)
			assert.Nil(t, binary)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want, "the error must name the missing field")
		})
	}
}

// countingRawFetcher stands in for the storage-service fetcher and records how
// many times the host actually reached for a binary.
type countingRawFetcher struct {
	calls  atomic.Int32
	binary []byte
	err    error
}

func (c *countingRawFetcher) FetchBinary(context.Context, string) ([]byte, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.binary, nil
}

func (c *countingRawFetcher) Close() error { return nil }

// testBinaryProvider builds a provider backed by raw, with an in-memory cache,
// so tests can assert on exactly when storage is touched.
func testBinaryProvider(t *testing.T, raw binaryfetch.RawFetcher) *binaryProvider {
	t.Helper()
	lggr := cllogger.Sugared(cllogger.Nop())
	return &binaryProvider{
		fetcher: binaryfetch.NewBinaryFetcherWithStore(lggr, binaryfetch.NewMemoryStore(), 1<<20),
		raw:     raw,
		timeout: 5 * time.Second,
	}
}

func TestBinaryProvider_CacheIdentityAndSize(t *testing.T) {
	raw := &countingRawFetcher{binary: []byte("binary")}
	p := testBinaryProvider(t, raw)
	for _, id := range []string{"workflow-1", "workflow-2", "../../escape"} {
		got, err := p.binaryFor(t.Context(), &confworkflowtypes.WorkflowExecution{
			WorkflowId: id, BinaryUrl: "loc", BinaryHash: sha256Sum(raw.binary),
		})
		require.NoError(t, err)
		assert.Equal(t, raw.binary, got)
	}
	assert.Equal(t, int32(1), raw.calls.Load())
	p.settings.MaxBinarySize = 1
	_, err := p.binaryFor(t.Context(), &confworkflowtypes.WorkflowExecution{
		WorkflowId: "workflow-1", BinaryUrl: "loc", BinaryHash: sha256Sum(raw.binary),
	})
	require.ErrorContains(t, err, "exceeds max size")
}

func TestNewBinaryProvider_CacheConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(withBinaryCacheDir(dir))
	oldCID, oldMax := *enclaveCID, *binaryCacheMaxBytes
	t.Cleanup(func() { *enclaveCID, *binaryCacheMaxBytes = oldCID, oldMax })
	for cid, bound := range []int{0, 10} {
		*enclaveCID, *binaryCacheMaxBytes = cid+16, bound
		p, err := newBinaryProvider(`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage:443","maxCacheBytes":5}`, cllogger.Sugared(cllogger.Nop()))
		require.NoError(t, err)
		require.NoError(t, p.raw.Close())
		raw := &countingRawFetcher{binary: []byte("binary")}
		p.raw = raw
		for range 2 {
			_, err := p.binaryFor(t.Context(), &confworkflowtypes.WorkflowExecution{
				WorkflowId: "workflow", BinaryUrl: "loc", BinaryHash: sha256Sum(raw.binary),
			})
			require.NoError(t, err)
		}
		if bound == 0 {
			assert.Equal(t, int32(2), raw.calls.Load(), "settings bound prevents caching an oversized binary")
		} else {
			assert.Equal(t, int32(1), raw.calls.Load(), "flag overrides settings bound")
		}
	}
	first, err := os.ReadDir(filepath.Join(dir, "16"))
	require.NoError(t, err)
	assert.Empty(t, first)
	second, err := os.ReadDir(filepath.Join(dir, "17"))
	require.NoError(t, err)
	assert.Len(t, second, 1, "different enclave CIDs must own separate cache directories")
}

func TestBinaryProvider_ArtifactHTTPPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("d2FzbQ=="))
	}))
	defer srv.Close()
	previous := *outboundAllowLocalForTests
	t.Cleanup(func() { *outboundAllowLocalForTests = previous })
	for _, allow := range []bool{false, true} {
		*outboundAllowLocalForTests = allow
		p, err := newBinaryProviderWithCache(hostStorageSettings{
			StorageKey: testStorageKeyHex, StorageServiceURL: "storage:443",
		}, t.TempDir(), 100, cllogger.Sugared(cllogger.Nop()))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, p.Close()) })
		got, err := p.raw.(*binaryfetch.StorageFetcher).Download(t.Context(), srv.URL)
		if allow {
			require.NoError(t, err)
			assert.Equal(t, []byte("wasm"), got)
		} else {
			require.Error(t, err, "production artifact downloads must reject plain HTTP and loopback")
		}
	}
}

func TestHandleInjectSettings_StorageRequiresRestart(t *testing.T) {
	initial := `{"storageKey":"` + testStorageKeyHex + `","storageServiceUrl":"storage:443","binaryFetchTimeout":"30s"}`
	settings, _, err := parseHostStorageSettings(initial)
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		provider *binaryProvider
		payload  string
		status   int
	}{
		{"unchanged", &binaryProvider{settings: settings}, initial, http.StatusNoContent},
		{"enclave setting", &binaryProvider{settings: settings}, strings.TrimSuffix(initial, "}") + `,"gatewayUrl":"https://new"}`, http.StatusNoContent},
		{"equivalent duration", &binaryProvider{settings: settings}, strings.Replace(initial, `"30s"`, `30000000000`, 1), http.StatusNoContent},
		{"rotation", &binaryProvider{settings: settings}, strings.Replace(initial, testStorageKeyHex, strings.Repeat("a", 64), 1), http.StatusConflict},
		{"remove", &binaryProvider{settings: settings}, `{}`, http.StatusConflict},
		{"provision", nil, initial, http.StatusConflict},
		{"partial", nil, `{"storageKey":"key"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &mockRoundTripper{response: &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}}
			host := NewHostServer(t.Context(), &http.Client{Transport: transport})
			t.Cleanup(host.cancel)
			host.binaries = tc.provider
			recorder := httptest.NewRecorder()
			host.handleInjectSettings(recorder, httptest.NewRequest(http.MethodPost, types.SettingsPath, strings.NewReader(tc.payload)))
			assert.Equal(t, tc.status, recorder.Code)
			if tc.status == http.StatusNoContent {
				require.Len(t, transport.requests, 1)
				var forwarded map[string]any
				require.NoError(t, json.NewDecoder(transport.requests[0].Body).Decode(&forwarded))
				assert.Equal(t, testStorageKeyHex, forwarded["storageKey"])
			} else {
				assert.Empty(t, transport.requests, "rejected settings must not reach the enclave")
			}
		})
	}
}
