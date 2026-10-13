package main

import (
	"encoding/hex"
	"testing"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

func TestNewBinaryProvider_DisabledWithoutStorageSettings(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	for name, settings := range map[string]string{
		"empty":           "",
		"whitespace":      "   ",
		"no storage key":  `{"storageServiceUrl":"storage:443"}`,
		"no storage url":  `{"storageKey":"` + testStorageKeyHex + `"}`,
		"unrelated app":   `{"gatewayUrl":"https://gateway"}`,
		"empty json body": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := newBinaryProviderWithCache(settings, t.TempDir(), 1024, lggr)
			require.NoError(t, err, "missing storage settings should disable fetching, not error")
			assert.Nil(t, p)
		})
	}
}

func TestNewBinaryProvider_RejectsMalformedSettings(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())

	_, err := newBinaryProviderWithCache("not json", t.TempDir(), 1024, lggr)
	require.Error(t, err)

	_, err = newBinaryProviderWithCache(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage:443","binaryFetchTimeout":"nope"}`,
		t.TempDir(), 1024, lggr,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binaryFetchTimeout")
}

func TestNewBinaryProvider_Enabled(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	p, err := newBinaryProviderWithCache(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443","binaryFetchTimeout":"30s"}`,
		t.TempDir(), 1024, lggr,
	)
	require.NoError(t, err)
	require.NotNil(t, p)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	assert.Equal(t, 30*1e9, float64(p.timeout))
}

// A nil provider is the disabled case and must stay safe to call.
func TestBinaryProvider_NilIsSafe(t *testing.T) {
	var p *binaryProvider
	binary, err := p.binaryFor(t.Context(), nil)
	assert.Nil(t, binary)
	assert.NoError(t, err)
	assert.NoError(t, p.Close())
}

// Incomplete executions degrade to no binary rather than erroring: the
// enclave validates the payload and reports the real error.
func TestBinaryProvider_SkipsIncompleteExecutions(t *testing.T) {
	lggr := cllogger.Sugared(cllogger.Nop())
	p, err := newBinaryProviderWithCache(
		`{"storageKey":"`+testStorageKeyHex+`","storageServiceUrl":"storage.invalid:443"}`,
		t.TempDir(), 1024, lggr,
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })

	for name, execution := range map[string]*confworkflowtypes.WorkflowExecution{
		"no workflow id": {BinaryUrl: "storage://b", BinaryHash: []byte{1}},
		"no binary url":  {WorkflowId: "wf", BinaryHash: []byte{1}},
		"no hash":        {WorkflowId: "wf", BinaryUrl: "storage://b"},
	} {
		t.Run(name, func(t *testing.T) {
			binary, err := p.binaryFor(t.Context(), execution)
			assert.Nil(t, binary)
			assert.NoError(t, err)
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
