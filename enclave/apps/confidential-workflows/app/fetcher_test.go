package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBinary is arbitrary raw bytes standing in for a brotli-compressed WASM
// binary (the exact bytes binary_hash covers).
var testBinary = []byte("fake-brotli-compressed-wasm-binary")

func testBinaryHash() []byte {
	h := sha256.Sum256(testBinary)
	return h[:]
}

// stubRawFetcher stands in for the storage-service RawFetcher: it returns
// pre-configured raw bytes per locator and counts calls.
type stubRawFetcher struct {
	mu    sync.Mutex
	data  map[string][]byte
	err   error
	calls atomic.Int32
}

func (s *stubRawFetcher) FetchBinary(_ context.Context, locator string) ([]byte, error) {
	s.calls.Add(1)
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

	got, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, nil)
	require.NoError(t, err)
	assert.Equal(t, testBinary, got)
}

func TestFetch_CacheHit(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), raw.calls.Load())

	got, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, nil)
	require.NoError(t, err)
	assert.Equal(t, testBinary, got)
	assert.Equal(t, int32(1), raw.calls.Load(), "expected cache hit, but fetcher was called again")
}

// Every lookup emits exactly one hit/miss event so the miss count can be read
// as a rate against total lookups.
func TestFetch_EmitsCacheOutcome(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))
	em := &recordingEmitter{}

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, em)
	require.NoError(t, err)
	require.Equal(t, 1, em.countOf(cacheLookupEvent))
	assert.Equal(t, cacheOutcomeMiss, em.lastDetails(cacheLookupEvent)["outcome"])

	_, err = f.Fetch(context.Background(), "loc", testBinaryHash(), raw, em)
	require.NoError(t, err)
	require.Equal(t, 2, em.countOf(cacheLookupEvent))
	assert.Equal(t, cacheOutcomeHit, em.lastDetails(cacheLookupEvent)["outcome"])
}

// A miss is recorded even when the backing fetch then fails: the lookup still
// did not find the binary in the cache.
func TestFetch_EmitsMissOnFetchError(t *testing.T) {
	raw := &stubRawFetcher{err: fmt.Errorf("storage down")}
	f := NewBinaryFetcher(logger.Test(t))
	em := &recordingEmitter{}

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, em)
	require.Error(t, err)
	require.Equal(t, 1, em.countOf(cacheLookupEvent))
	assert.Equal(t, cacheOutcomeMiss, em.lastDetails(cacheLookupEvent)["outcome"])
}

// Validation failures happen before the cache is consulted, so they must not
// record a lookup at all.
func TestFetch_NoCacheEventOnValidationError(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))
	em := &recordingEmitter{}

	_, err := f.Fetch(context.Background(), "loc", nil, raw, em)
	require.Error(t, err)
	assert.Equal(t, 0, em.countOf(cacheLookupEvent))
}

func TestFetch_HashMismatch(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", make([]byte, 32), raw, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestFetch_RawError(t *testing.T) {
	raw := &stubRawFetcher{err: fmt.Errorf("storage down")}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), raw, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage down")
}

func TestFetch_EmptyHash_Rejected(t *testing.T) {
	raw := &stubRawFetcher{data: map[string][]byte{"loc": testBinary}}
	f := NewBinaryFetcher(logger.Test(t))

	_, err := f.Fetch(context.Background(), "loc", nil, raw, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary_hash is required")
}

func TestFetch_NilRawFetcher_Rejected(t *testing.T) {
	f := NewBinaryFetcher(logger.Test(t))
	_, err := f.Fetch(context.Background(), "loc", testBinaryHash(), nil, nil)
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
	f := newBinaryFetcher(logger.Test(t), 25) // fits 2 entries of 10 bytes

	fetch := func(i int) {
		t.Helper()
		got, err := f.Fetch(context.Background(), fmt.Sprintf("loc-%d", i), hashes[i], raw, nil)
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
	f := newBinaryFetcher(logger.Test(t), 25)

	fetch := func(i int) {
		t.Helper()
		got, err := f.Fetch(context.Background(), fmt.Sprintf("loc-%d", i), hashes[i], raw, nil)
		require.NoError(t, err)
		assert.Equal(t, binaries[i], got)
	}

	fetch(0)
	fetch(1)
	fetch(0) // refresh 0 -> LRU order [0, 1]
	fetch(2) // evicts 1

	f.mu.Lock()
	_, has0 := f.items[fmt.Sprintf("%x", hashes[0])]
	_, has1 := f.items[fmt.Sprintf("%x", hashes[1])]
	f.mu.Unlock()
	assert.True(t, has0, "binary 0 should still be cached after refresh")
	assert.False(t, has1, "binary 1 should have been evicted")
}
