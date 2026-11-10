package binaryfetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// NewBinaryFetcher returns a fetcher caching in memory, for tests.
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
// the SHA-256, and caches under that hash. The bytes returned by raw are the
// exact bytes binaryHash covers (no transport encoding).
//
// Verification also covers persisted entries, which may have been corrupted.
func (f *BinaryFetcher) Fetch(ctx context.Context, locator string, binaryHash []byte, raw RawFetcher) ([]byte, error) {
	if len(binaryHash) != sha256.Size {
		return nil, fmt.Errorf("binary_hash must be a %d-byte SHA-256 hash", sha256.Size)
	}
	if raw == nil {
		return nil, fmt.Errorf("storage credentials not yet provisioned")
	}

	cacheKey := hex.EncodeToString(binaryHash)
	binary, err, _ := f.group.Do(cacheKey, func() (any, error) {
		if cached, ok := f.cache.Get(cacheKey); ok {
			if err := Verify(cached, binaryHash); err == nil {
				return cached, nil
			}
			f.cache.Delete(cacheKey)
		}
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

// Verify checks binary against its expected SHA-256. The enclave independently
// repeats this check before execution; host verification is not trusted.
func Verify(binary, binaryHash []byte) error {
	actual := sha256.Sum256(binary)
	if !bytes.Equal(actual[:], binaryHash) {
		return fmt.Errorf("binary hash mismatch: expected %x, got %x", binaryHash, actual[:])
	}
	return nil
}
