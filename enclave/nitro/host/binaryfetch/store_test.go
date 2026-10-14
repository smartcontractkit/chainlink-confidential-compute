package binaryfetch

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeImpls runs a shared contract over every Store implementation, so the
// enclave's memory store and the host's disk store stay behaviourally
// interchangeable.
func storeImpls(t *testing.T) map[string]Store {
	t.Helper()
	disk, err := NewDiskStore(t.TempDir())
	require.NoError(t, err)
	return map[string]Store{
		"memory": NewMemoryStore(),
		"disk":   disk,
	}
}

func TestStore_PutGetDelete(t *testing.T) {
	for name, s := range storeImpls(t) {
		t.Run(name, func(t *testing.T) {
			_, ok := s.Get("absent")
			assert.False(t, ok)

			require.NoError(t, s.Put("key-1", testBinary))
			got, ok := s.Get("key-1")
			require.True(t, ok)
			assert.Equal(t, testBinary, got)

			s.Delete("key-1")
			_, ok = s.Get("key-1")
			assert.False(t, ok)

			// Deleting an absent key is not an error.
			s.Delete("key-1")
		})
	}
}

func TestStore_PutReplaces(t *testing.T) {
	for name, s := range storeImpls(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, s.Put("key-1", []byte("first")))
			require.NoError(t, s.Put("key-1", []byte("second")))
			got, ok := s.Get("key-1")
			require.True(t, ok)
			assert.Equal(t, []byte("second"), got)
		})
	}
}

func TestStore_Entries(t *testing.T) {
	for name, s := range storeImpls(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, s.Put("key-1", []byte("12345")))
			require.NoError(t, s.Put("key-2", []byte("123")))

			entries, err := s.Entries()
			require.NoError(t, err)
			assert.Equal(t, map[string]int{"key-1": 5, "key-2": 3}, entries)
		})
	}
}

func TestDiskStore_RejectsUnsafeKeys(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	require.NoError(t, err)

	for _, key := range []string{"", "../escape", "a/b", "a.b", "with space"} {
		require.Error(t, s.Put(key, testBinary), "key %q should be rejected", key)
		_, ok := s.Get(key)
		assert.False(t, ok, "key %q should not be readable", key)
	}

	// Nothing escaped the cache directory.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestDiskStore_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	first, err := NewDiskStore(dir)
	require.NoError(t, err)
	require.NoError(t, first.Put("key-1", testBinary))

	// A new process pointed at the same volume sees the previous entries.
	second, err := NewDiskStore(dir)
	require.NoError(t, err)
	got, ok := second.Get("key-1")
	require.True(t, ok)
	assert.Equal(t, testBinary, got)
}

func TestDiskStore_IgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o700))

	s, err := NewDiskStore(dir)
	require.NoError(t, err)
	require.NoError(t, s.Put("key-1", []byte("12345")))

	entries, err := s.Entries()
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"key-1": 5}, entries)
}

func TestCache_AdoptsExistingEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.Put("key-1", []byte("1234567890")))

	c := NewCache(logger.Test(t), store, 100)
	assert.Equal(t, 10, c.Bytes(), "pre-existing entries should be accounted for")
	got, ok := c.Get("key-1")
	require.True(t, ok)
	assert.Equal(t, []byte("1234567890"), got)
}

func TestCache_AdoptedEntriesTrimmedToBound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	require.NoError(t, err)
	for _, k := range []string{"key-1", "key-2", "key-3"} {
		require.NoError(t, store.Put(k, []byte("1234567890")))
	}

	// 30 bytes on disk, bound of 25: the cache must shed entries at startup
	// rather than inheriting an over-budget directory.
	c := NewCache(logger.Test(t), store, 25)
	assert.LessOrEqual(t, c.Bytes(), 25)

	remaining, err := store.Entries()
	require.NoError(t, err)
	assert.Len(t, remaining, 2, "evicted entries should be deleted from the store")
}

func TestCache_EvictionDeletesFromStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	require.NoError(t, err)

	c := NewCache(logger.Test(t), store, 25)
	c.Put("key-1", []byte("1234567890"))
	c.Put("key-2", []byte("1234567890"))
	c.Put("key-3", []byte("1234567890")) // 30 > 25, evicts key-1

	_, ok := store.Get("key-1")
	assert.False(t, ok, "evicted entry should be removed from disk, not just the index")
	assert.Equal(t, 20, c.Bytes())
}

func TestCache_OversizedValueNotCached(t *testing.T) {
	c := NewCache(logger.Test(t), NewMemoryStore(), 5)
	c.Put("key-1", []byte("1234567890"))
	_, ok := c.Get("key-1")
	assert.False(t, ok)
	assert.Equal(t, 0, c.Bytes())
}

func TestCache_GetDropsIndexWhenStoreLostEntry(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDiskStore(dir)
	require.NoError(t, err)

	c := NewCache(logger.Test(t), store, 100)
	c.Put("key-1", []byte("1234567890"))
	require.Equal(t, 10, c.Bytes())

	// Something outside the process cleared the volume.
	store.Delete("key-1")

	_, ok := c.Get("key-1")
	assert.False(t, ok)
	assert.Equal(t, 0, c.Bytes(), "byte accounting should not drift when the store loses an entry")
}

func TestCache_SetMaxCacheBytesEvicts(t *testing.T) {
	store := NewMemoryStore()
	c := NewCache(logger.Test(t), store, 100)
	c.Put("key-1", []byte("1234567890"))
	c.Put("key-2", []byte("1234567890"))

	c.SetMaxCacheBytes(10)
	assert.Equal(t, 10, c.Bytes())
	_, ok := store.Get("key-1")
	assert.False(t, ok, "least-recently-used entry should be evicted from the store")

	// Non-positive values are ignored.
	c.SetMaxCacheBytes(0)
	assert.Equal(t, 10, c.Bytes())
}

// Concurrent Puts for different keys must not overshoot the bound. Without
// reserving the incoming bytes before releasing the lock, every writer sees the
// same free space, evicts to fit, and then publishes -- so the total lands well
// over maxCacheBytes.
func TestCache_ConcurrentPutsRespectBound(t *testing.T) {
	const (
		writers   = 16
		valueSize = 10
		maxBytes  = 50 // fits 5 entries
	)
	store := NewMemoryStore()
	c := NewCache(logger.Test(t), store, maxBytes)

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put(fmt.Sprintf("key-%02d", i), bytes.Repeat([]byte("x"), valueSize))
		}(i)
	}
	wg.Wait()

	assert.LessOrEqual(t, c.Bytes(), maxBytes, "cache must never exceed its byte bound")

	// Accounting must also match what the store actually holds.
	entries, err := store.Entries()
	require.NoError(t, err)
	total := 0
	for _, size := range entries {
		total += size
	}
	assert.Equal(t, total, c.Bytes(), "byte accounting must match the store contents")
}

// A store write failure must give back the bytes Put reserved, or the cache
// slowly starves itself.
func TestCache_FailedPutReleasesReservation(t *testing.T) {
	store := &failingStore{Store: NewMemoryStore(), fail: true}
	c := NewCache(logger.Test(t), store, 100)

	c.Put("key-1", []byte("1234567890"))
	assert.Zero(t, c.Bytes(), "a failed write must not leak reserved bytes")

	// The cache is still usable for its full capacity afterwards.
	store.fail = false
	c.Put("key-2", []byte("1234567890"))
	assert.Equal(t, 10, c.Bytes())
}

// failingStore makes Put fail on demand.
type failingStore struct {
	Store
	fail bool
}

func (s *failingStore) Put(key string, value []byte) error {
	if !s.fail {
		return s.Store.Put(key, value)
	}
	return fmt.Errorf("disk full")
}

// Keys that could escape the cache directory must be refused at path
// resolution, independent of the character allowlist in safeKey.
func TestDiskStore_PathContainsKeysToCacheDir(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	require.NoError(t, err)

	for _, key := range []string{
		"../escape",
		"../../etc/passwd",
		"sub/dir",
		"..",
		".",
		"with\x00null",
	} {
		_, err := s.path(key)
		assert.Error(t, err, "key %q must not resolve to a path", key)
	}

	// A legitimate key resolves inside the directory.
	resolved, err := s.path("abc123")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "abc123"+binaryFileExt), resolved)
}
