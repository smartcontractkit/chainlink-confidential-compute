package app

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/confidential-compute/types"
)

// BinaryFetcher verifies WASM binaries against their SHA-256 hash and caches the
// results in a size-bounded LRU cache keyed by hash. The raw bytes are supplied
// by a RawFetcher (the storage-service gRPC fetcher); BinaryFetcher owns only
// integrity verification and caching, so the storage service stays untrusted.
type BinaryFetcher struct {
	logger logger.Logger

	mu            sync.Mutex
	maxCacheBytes int
	cacheBytes    int                      // current total size of cached values
	items         map[string]*list.Element // hex(sha256) -> list element
	evictList     *list.List               // front = most recent, back = least recent
}

type cacheEntry struct {
	key   string
	value []byte
}

func NewBinaryFetcher(lggr logger.Logger) *BinaryFetcher {
	return newBinaryFetcher(lggr, types.DefaultMaxBinaryCacheBytes)
}

func newBinaryFetcher(lggr logger.Logger, maxCacheBytes int) *BinaryFetcher {
	return &BinaryFetcher{
		logger:        lggr,
		maxCacheBytes: maxCacheBytes,
		items:         make(map[string]*list.Element),
		evictList:     list.New(),
	}
}

// Fetch returns the workflow binary for locator, verified against binaryHash. On
// a cache miss it fetches the raw bytes via raw (the storage fetcher), verifies
// the SHA-256, and caches. The bytes returned by raw are the exact bytes
// binary_hash covers (no transport encoding).
func (f *BinaryFetcher) Fetch(ctx context.Context, locator string, binaryHash []byte, raw RawFetcher) ([]byte, error) {
	if len(binaryHash) == 0 {
		return nil, fmt.Errorf("binary_hash is required for integrity verification")
	}
	if raw == nil {
		return nil, fmt.Errorf("storage credentials not yet provisioned")
	}

	cacheKey := fmt.Sprintf("%x", binaryHash)
	if cached, ok := f.cacheGet(cacheKey); ok {
		return cached, nil
	}

	binary, err := raw.FetchBinary(ctx, locator)
	if err != nil {
		return nil, fmt.Errorf("fetching binary: %w", err)
	}

	actual := sha256.Sum256(binary)
	if !bytes.Equal(actual[:], binaryHash) {
		return nil, fmt.Errorf("binary hash mismatch: expected %x, got %x", binaryHash, actual[:])
	}

	f.cachePut(cacheKey, binary)
	f.logger.Infof("fetched and cached binary (%d bytes, cache: %d/%d bytes)", len(binary), f.cacheBytes, f.maxCacheBytes)
	return binary, nil
}

// SetMaxCacheBytes updates the cache size bound, evicting least-recently-used
// entries if the new bound is smaller than the current usage. A non-positive
// value is ignored.
func (f *BinaryFetcher) SetMaxCacheBytes(maxCacheBytes int) {
	if maxCacheBytes <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxCacheBytes = maxCacheBytes
	for f.cacheBytes > f.maxCacheBytes && f.evictList.Len() > 0 {
		oldest := f.evictList.Back()
		entry := oldest.Value.(*cacheEntry)
		f.evictList.Remove(oldest)
		delete(f.items, entry.key)
		f.cacheBytes -= len(entry.value)
	}
}

// cacheGet returns the cached binary for the given key, promoting it to most recent.
func (f *BinaryFetcher) cacheGet(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	el, ok := f.items[key]
	if !ok {
		return nil, false
	}
	f.evictList.MoveToFront(el)
	return el.Value.(*cacheEntry).value, true
}

// cachePut inserts a binary into the LRU cache, evicting old entries if needed.
// If the key was already inserted by another goroutine, it just promotes it.
func (f *BinaryFetcher) cachePut(key string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if el, ok := f.items[key]; ok {
		f.evictList.MoveToFront(el)
		return
	}
	for f.cacheBytes+len(value) > f.maxCacheBytes && f.evictList.Len() > 0 {
		oldest := f.evictList.Back()
		entry := oldest.Value.(*cacheEntry)
		f.evictList.Remove(oldest)
		delete(f.items, entry.key)
		f.cacheBytes -= len(entry.value)
	}
	el := f.evictList.PushFront(&cacheEntry{key: key, value: value})
	f.items[key] = el
	f.cacheBytes += len(value)
}
