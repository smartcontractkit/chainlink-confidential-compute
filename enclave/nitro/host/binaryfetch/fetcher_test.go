package binaryfetch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBinary is arbitrary raw bytes standing in for a brotli-compressed WASM
// binary (the exact bytes binary_hash covers).
var testBinary = []byte("fake-brotli-compressed-wasm-binary")

// cacheKeyFor mirrors how the host keys entries: by binary hash.
func cacheKeyFor(hash []byte) string { return fmt.Sprintf("%x", hash) }

func testBinaryHash() []byte {
	h := sha256.Sum256(testBinary)
	return h[:]
}

// stubRawFetcher stands in for the storage-service RawFetcher: it returns
// pre-configured raw bytes per locator and counts calls.
type stubRawFetcher struct {
	mu      sync.Mutex
	data    map[string][]byte
	err     error
	calls   atomic.Int32
	release <-chan struct{}
}

func (s *stubRawFetcher) FetchBinary(_ context.Context, locator string) ([]byte, error) {
	s.calls.Add(1)
	if s.release != nil {
		<-s.release
	}
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[locator]
	if !ok {
		return nil, fmt.Errorf("no binary for locator %q", locator)
	}
	return b, nil
}

func (s *stubRawFetcher) Close() error { return nil }

func TestFetch_Success(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	got, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw)
	require.NoError(t, err)
	assert.Equal(t, testBinary, got)
}

func TestFetch_CacheHit(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw)
	require.NoError(t, err)
	assert.Equal(t, int32(1), raw.calls.Load())

	got, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw)
	require.NoError(t, err)
	assert.Equal(t, testBinary, got)
	assert.Equal(t, int32(1), raw.calls.Load(), "expected cache hit, but fetcher was called again")
}

func TestFetch_HashMismatch(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", make([]byte, 32), raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestFetch_RawError(t *testing.T) {
	raw := &stubRawFetcher{err: fmt.Errorf("storage down")}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage down")
}

func TestFetch_EmptyHash_Rejected(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", nil, raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary_hash must be a 32-byte")
}

func TestFetch_NilRawFetcher_Rejected(t *testing.T) {
	f := NewBinaryFetcher(logger.Test(t))
	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credentials not yet provisioned")
}

func lruBinaries(t *testing.T) (binaries [][]byte, hashes [][]byte, data map[string][]byte) {
	t.Helper()
	binaries = make([][]byte, 3)
	hashes = make([][]byte, 3)
	data = make(map[string][]byte)
	for i := range binaries {
		binaries[i] = []byte(fmt.Sprintf("binary-%03d", i)) // 10 bytes each
		h := sha256.Sum256(binaries[i])
		hashes[i] = h[:]
		data[fmt.Sprintf("loc-%d", i)] = binaries[i]
	}
	return binaries, hashes, data
}

func TestFetch_LRU_EvictsOldest(t *testing.T) {
	binaries, hashes, data := lruBinaries(t)
	raw := &stubRawFetcher{data: data}
	f := NewBinaryFetcherWithStore(logger.Test(t), NewMemoryStore(), 25) // fits 2 entries of 10 bytes

	fetch := func(i int) {
		t.Helper()
		got, err := f.Fetch(context.Background(), fmt.Sprintf("loc-%d", i), hashes[i], raw)
		require.NoError(t, err)
		assert.Equal(t, binaries[i], got)
	}

	fetch(0)
	fetch(1)
	assert.Equal(t, int32(2), raw.calls.Load())

	fetch(2) // 30 > 25, evicts binary 0
	assert.Equal(t, int32(3), raw.calls.Load())

	fetch(1) // still cached
	assert.Equal(t, int32(3), raw.calls.Load(), "binary 1 should be a cache hit")

	fetch(0) // was evicted, re-fetch
	assert.Equal(t, int32(4), raw.calls.Load(), "binary 0 should have been evicted and re-fetched")
}

func TestFetch_LRU_AccessRefreshesEntry(t *testing.T) {
	binaries, hashes, data := lruBinaries(t)
	raw := &stubRawFetcher{data: data}
	f := NewBinaryFetcherWithStore(logger.Test(t), NewMemoryStore(), 25)

	fetch := func(i int) {
		t.Helper()
		got, err := f.Fetch(context.Background(), fmt.Sprintf("loc-%d", i), hashes[i], raw)
		require.NoError(t, err)
		assert.Equal(t, binaries[i], got)
	}

	fetch(0)
	fetch(1)
	fetch(0) // refresh 0 -> LRU order [0, 1]
	fetch(2) // evicts 1

	calls := raw.calls.Load()
	fetch(0)
	assert.Equal(t, calls, raw.calls.Load(), "binary 0 should still be cached after refresh")
	fetch(1)
	assert.Equal(t, calls+1, raw.calls.Load(), "binary 1 should have been evicted")
}

// A corrupted cache entry must be replaced, not just bypassed. The refetch
// repairs the cache, so a later execution still succeeds once storage is
// unavailable -- otherwise every execution re-downloads and the workflow breaks
// outright the moment storage goes away.
func TestFetch_CorruptedEntryIsReplaced(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	require.NoError(t, err)
	f := NewBinaryFetcherWithStore(logger.Test(t), store, 1<<20)
	key := cacheKeyFor(testBinaryHash())

	// Seed the cache with bytes that do not match the hash, as a damaged disk
	// cache would hold.
	f.cache.Put(key, []byte("corrupted-bytes"))
	require.Equal(t, len("corrupted-bytes"), f.cache.Bytes())

	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	got, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw)
	require.NoError(t, err)
	assert.Equal(t, testBinary, got)
	assert.Equal(t, int32(1), raw.calls.Load())

	// The repaired entry is what the store now holds.
	cached, ok := store.Get(key)
	require.True(t, ok, "entry must still be cached after repair")
	assert.Equal(t, testBinary, cached, "the corrupted bytes must have been replaced")
	assert.Equal(t, len(testBinary), f.cache.Bytes(), "accounting must track the replacement")

	// With storage now unavailable the execution still succeeds from cache.
	dead := &stubRawFetcher{err: fmt.Errorf("storage unavailable")}
	store, err = NewDiskStore(dir)
	require.NoError(t, err)
	f = NewBinaryFetcherWithStore(logger.Test(t), store, 1<<20)
	got, err = f.Fetch(context.Background(), "loc", testBinaryHash(), dead)
	require.NoError(t, err, "a repaired cache must serve the binary without storage")
	assert.Equal(t, testBinary, got)
	assert.Zero(t, dead.calls.Load(), "storage must not be consulted on a healthy cache hit")
}

func TestFetch_ConcurrentHashes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}, release: release}
		f := NewBinaryFetcher(logger.Test(t))
		var wg sync.WaitGroup
		for i, hash := range [][]byte{testBinaryHash(), make([]byte, sha256.Size)} {
			wg.Go(func() {
				got, err := f.Fetch(t.Context(), "loc", hash, raw)
				if i == 0 {
					assert.NoError(t, err)
					assert.Equal(t, testBinary, got)
				} else {
					assert.ErrorContains(t, err, "hash mismatch", "each caller's hash must be checked")
				}
			})
			synctest.Wait()
		}
		close(release)
		wg.Wait()
	})
}

// If the refetch itself fails, the bad entry is still gone: better to fail
// loudly than to keep serving bytes that do not match the signed hash.
func TestFetch_CorruptedEntryDroppedWhenRefetchFails(t *testing.T) {
	store := NewMemoryStore()
	f := NewBinaryFetcherWithStore(logger.Test(t), store, 1<<20)
	key := cacheKeyFor(testBinaryHash())
	f.cache.Put(key, []byte("corrupted-bytes"))

	dead := &stubRawFetcher{err: fmt.Errorf("storage unavailable")}
	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), dead)
	require.Error(t, err)

	_, ok := store.Get(key)
	assert.False(t, ok, "the corrupted entry must not survive a failed refetch")
	assert.Zero(t, f.cache.Bytes(), "accounting must not leak the dropped entry")
}
