package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDonKey(t *testing.T) {
	for capRegDONName, want := range map[string]struct {
		name  string
		shard int
	}{
		"wf":          {"wf", 0},
		"wf_shard-0":  {"wf", 0},
		"wf_shard-12": {"wf", 12},
		"a_b_shard-1": {"a_b", 1},
		"wf_shard-":   {"wf_shard-", 0},
		"wf_shard-x":  {"wf_shard-x", 0},
		"_shard-1":    {"_shard-1", 0},
		"":            {"", 0},
	} {
		name, shard := ParseCapRegDONName(capRegDONName)
		assert.Equal(t, want.name, name, capRegDONName)
		assert.Equal(t, want.shard, shard, capRegDONName)
	}
}

func TestEnclaveConfigs(t *testing.T) {
	a := EnclaveConfig{Signers: [][]byte{[]byte("a1"), []byte("a2")}, MasterPublicKey: []byte("m"), T: 1, F: 1}
	b := EnclaveConfig{Signers: [][]byte{[]byte("b1")}, MasterPublicKey: []byte("m"), T: 1}

	c := NewEnclaveConfigs()
	_, _, ok := c.Default()
	assert.False(t, ok)

	require.NoError(t, c.Set("wf", a))
	require.NoError(t, c.Set("wf_shard-1", b))
	require.Error(t, c.Set("other", EnclaveConfig{Signers: [][]byte{[]byte("a2")}}))
	require.NoError(t, c.Set("wf", EnclaveConfig{Signers: [][]byte{[]byte("a2")}}), "a DON may keep its own signers")
	require.NoError(t, c.Set("wf", a))

	donName, ok := c.DONForSigner([]byte("b1"))
	assert.True(t, ok)
	assert.Equal(t, "wf_shard-1", donName)
	_, ok = c.DONForSigner([]byte("x"))
	assert.False(t, ok)
	assert.Len(t, c.AllSigners(), 3)

	donName, cfg, ok := c.Default()
	require.True(t, ok)
	assert.Equal(t, "wf", donName)
	assert.Equal(t, a, cfg)

	_, ok = c.Lookup("unknown")
	assert.False(t, ok)

	clone := c.Clone()
	c.Delete("wf")
	_, ok = c.DONForSigner([]byte("a1"))
	assert.False(t, ok)
	_, ok = clone.Get("wf")
	assert.True(t, ok, "clones are independent")

	legacy := NewEnclaveConfigs()
	require.NoError(t, legacy.Set("", b))
	cfg, ok = legacy.Lookup("wf")
	require.True(t, ok, "the legacy config serves any DON")
	assert.Equal(t, b, cfg)
}
