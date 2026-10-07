package framework

import "testing"

// TestCachedPublicKeysMatch guards the reshare-safety check on the all-cache-hit
// path: a batch may only be served from cache when every entry agrees on the
// response public key (including empty vs present), since all ciphertexts in a
// request are decrypted under a single MasterPublicKey. A mismatch (e.g. secret A
// cached before a reshare, secret B after) must be treated as a cache miss so the
// whole batch is refetched.
func TestCachedPublicKeysMatch(t *testing.T) {
	key1 := []byte("dkg-generation-1")
	key2 := []byte("dkg-generation-2")

	tests := []struct {
		name   string
		cached []*cachedEDKS
		want   bool
	}{
		{name: "empty batch", cached: nil, want: true},
		{name: "single entry with key", cached: []*cachedEDKS{{rawVaultPublicKey: key1}}, want: true},
		{name: "single entry without key", cached: []*cachedEDKS{{}}, want: true},
		{name: "all same key", cached: []*cachedEDKS{{rawVaultPublicKey: key1}, {rawVaultPublicKey: key1}}, want: true},
		{name: "all empty", cached: []*cachedEDKS{{}, {}}, want: true},
		{name: "different keys", cached: []*cachedEDKS{{rawVaultPublicKey: key1}, {rawVaultPublicKey: key2}}, want: false},
		{name: "empty vs present", cached: []*cachedEDKS{{}, {rawVaultPublicKey: key1}}, want: false},
		{name: "present vs empty", cached: []*cachedEDKS{{rawVaultPublicKey: key1}, {}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cachedPublicKeysMatch(tt.cached); got != tt.want {
				t.Fatalf("cachedPublicKeysMatch = %v, want %v", got, tt.want)
			}
		})
	}
}
