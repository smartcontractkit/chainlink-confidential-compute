package main

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/host/binaryfetch"
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
		"no storage key":  `{"storageServiceUrl":"storage:443"}`,
		"no storage url":  `{"storageKey":"` + testStorageKeyHex + `"}`,
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
}

func TestNewBinaryProvider_Enabled(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	t.Cleanup(withBinaryCacheDir(t.TempDir()))
	p, err := newBinaryProvider(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443","binaryFetchTimeout":"30s"}`,
		lggr,
	)
	require.NoError(t, err)
	require.NotNil(t, p)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	assert.Equal(t, 30*1e9, float64(p.timeout))
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
	assert.NoError(t, err)
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

func TestCacheKey(t *testing.T) {
	// Hex workflow IDs pass through unchanged, so the cache is readable.
	id := "0a1b2c3d4e5f"
	assert.Equal(t, id, cacheKey(id))

	// Anything else is hex-encoded rather than trusted as a filename.
	for _, unsafe := range []string{"../../etc/passwd", "with/slash", "with space"} {
		got := cacheKey(unsafe)
		assert.Equal(t, hex.EncodeToString([]byte(unsafe)), got)
		assert.NotContains(t, got, "/")
		assert.NotContains(t, got, "..")
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
		logger:  lggr,
	}
}
