package binaryfetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"golang.org/x/sync/singleflight"
)

// BinaryFetcher verifies WASM binaries against their SHA-256 hash and caches the
// results in a size-bounded LRU over a Store. The raw bytes are supplied by a
// RawFetcher (the storage-service gRPC fetcher); BinaryFetcher owns only
// integrity verification and caching, so the storage service stays untrusted.
type BinaryFetcher struct {
	logger logger.Logger
	cache  *Cache
	// group collapses concurrent fetches of the same key into one upstream
	// call, so a burst of requests for a cold binary downloads it once.
	group singleflight.Group
}

// NewBinaryFetcher returns a fetcher caching in memory, for use inside the
// enclave where binaries must never touch disk.
func NewBinaryFetcher(lggr logger.Logger) *BinaryFetcher {
	return NewBinaryFetcherWithStore(lggr, NewMemoryStore(), types.DefaultMaxBinaryCacheBytes)
}

// NewBinaryFetcherWithStore returns a fetcher caching into store, bounded to
// maxCacheBytes.
func NewBinaryFetcherWithStore(lggr logger.Logger, store Store, maxCacheBytes int) *BinaryFetcher {
	return &BinaryFetcher{
		logger: lggr,
		cache:  NewCache(lggr, store, maxCacheBytes),
	}
}

// Fetch returns the workflow binary for locator, verified against binaryHash. On
// a cache miss it fetches the raw bytes via raw (the storage fetcher), verifies
// the SHA-256, and caches under cacheKey. The bytes returned by raw are the
// exact bytes binaryHash covers (no transport encoding).
//
// cacheKey selects what the entry is keyed by: the enclave keys by binary hash,
// the host by workflow ID. Verification against binaryHash is unconditional
// either way, so a poisoned cache fails closed rather than executing.
func (f *BinaryFetcher) Fetch(ctx context.Context, cacheKey, locator string, binaryHash []byte, raw RawFetcher) ([]byte, error) {
	if cacheKey == "" {
		return nil, fmt.Errorf("cache key is required")
	}
	if len(binaryHash) == 0 {
		return nil, fmt.Errorf("binary_hash is required for integrity verification")
	}
	if raw == nil {
		return nil, fmt.Errorf("storage credentials not yet provisioned")
	}

	if cached, ok := f.cache.Get(cacheKey); ok {
		// A cache entry keyed by something other than the hash (the host's
		// workflow ID) is only valid if it still matches the hash the request
		// carries, so verify on the hit path too.
		if err := Verify(cached, binaryHash); err != nil {
			f.logger.Warnf("cached binary %q failed verification, re-fetching: %v", cacheKey, err)
		} else {
			return cached, nil
		}
	}

	binary, err, _ := f.group.Do(cacheKey, func() (any, error) {
		binary, err := raw.FetchBinary(ctx, locator)
		if err != nil {
			return nil, fmt.Errorf("fetching binary: %w", err)
		}
		if err := Verify(binary, binaryHash); err != nil {
			return nil, err
		}
		f.cache.Put(cacheKey, binary)
		f.logger.Infof("fetched and cached binary (%d bytes, cache: %d bytes)", len(binary), f.cache.Bytes())
		return binary, nil
	})
	if err != nil {
		return nil, err
	}
	return binary.([]byte), nil
}

// SetMaxCacheBytes updates the cache size bound, evicting least-recently-used
// entries if the new bound is smaller than the current usage. A non-positive
// value is ignored.
func (f *BinaryFetcher) SetMaxCacheBytes(maxCacheBytes int) {
	f.cache.SetMaxCacheBytes(maxCacheBytes)
}

// Verify checks binary against its expected SHA-256. This is the only thing
// standing between untrusted bytes and execution in the TEE, so it is applied
// to every binary regardless of where it came from.
func Verify(binary, binaryHash []byte) error {
	actual := sha256.Sum256(binary)
	if !bytes.Equal(actual[:], binaryHash) {
		return fmt.Errorf("binary hash mismatch: expected %x, got %x", binaryHash, actual[:])
	}
	return nil
}
