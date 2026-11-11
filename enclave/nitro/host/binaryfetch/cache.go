package binaryfetch

import (
	"container/list"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Cache is a size-bounded LRU index over a Store. It owns the eviction policy
// and byte accounting. Store I/O and index updates are serialized so eviction
// cannot delete a newly published entry or race the capacity check.
type Cache struct {
	logger logger.Logger
	store  Store

	mu            sync.Mutex
	maxCacheBytes int
	cacheBytes    int                      // current total size of cached values
	items         map[string]*list.Element // key -> list element
	evictList     *list.List               // front = most recent, back = least recent
}

type cacheEntry struct {
	key  string
	size int
}

// NewCache returns a Cache over store bounded to maxCacheBytes. Entries already
// present in the store (a disk cache that outlived the process) are adopted, so
// a restarted host starts warm instead of re-fetching everything.
func NewCache(lggr logger.Logger, store Store, maxCacheBytes int) *Cache {
	c := &Cache{
		logger:        lggr,
		store:         store,
		maxCacheBytes: maxCacheBytes,
		items:         make(map[string]*list.Element),
		evictList:     list.New(),
	}
	existing, err := store.Entries()
	if err != nil {
		lggr.Warnf("reading existing cache entries: %v", err)
		return c
	}
	for key, size := range existing {
		el := c.evictList.PushFront(&cacheEntry{key: key, size: size})
		c.items[key] = el
		c.cacheBytes += size
	}
	// LRU order across a restart is unknown, so trim to the bound immediately
	// rather than letting the first Put discover the overage.
	c.mu.Lock()
	c.evictToFitLocked(0)
	c.mu.Unlock()
	return c
}

// Get returns the cached binary for key, promoting it to most recent.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.evictList.MoveToFront(el)

	value, found := c.store.Get(key)
	if !found {
		// The store lost the entry behind our back (disk cache cleared, file
		// removed). Drop the index entry so accounting stays truthful.
		c.removeLocked(key)
		return nil, false
	}
	return value, true
}

// Put stores value under key, evicting least-recently-used entries to stay
// within the byte bound. A value larger than the whole bound is not cached.
func (c *Cache) Put(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(value) > c.maxCacheBytes {
		c.logger.Warnf("binary (%d bytes) exceeds cache bound (%d bytes), not caching", len(value), c.maxCacheBytes)
		return
	}
	if el, ok := c.items[key]; ok {
		c.evictList.MoveToFront(el)
		return
	}
	c.evictToFitLocked(len(value))

	if err := c.store.Put(key, value); err != nil {
		// A cache write failure is not fatal: the caller already holds the
		// bytes, so log and continue uncached rather than failing the request.
		c.logger.Warnf("caching binary %q: %v", key, err)
		return
	}

	el := c.evictList.PushFront(&cacheEntry{key: key, size: len(value)})
	c.items[key] = el
	c.cacheBytes += len(value)
}

// Delete removes key from the index and the store. Used to invalidate an entry
// whose bytes no longer match the hash they are supposed to have.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
	c.store.Delete(key)
}

// Bytes returns the total size of the cached entries.
func (c *Cache) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cacheBytes
}

// evictToFitLocked drops least-recently-used entries until incoming more bytes
// fits within the bound. Callers must hold c.mu.
func (c *Cache) evictToFitLocked(incoming int) {
	for c.cacheBytes+incoming > c.maxCacheBytes && c.evictList.Len() > 0 {
		oldest := c.evictList.Back()
		entry := oldest.Value.(*cacheEntry)
		c.removeLocked(entry.key)
		c.store.Delete(entry.key)
	}
}

// removeLocked drops a single key from the index. Callers must hold c.mu.
func (c *Cache) removeLocked(key string) {
	el, ok := c.items[key]
	if !ok {
		return
	}
	c.evictList.Remove(el)
	delete(c.items, key)
	c.cacheBytes -= el.Value.(*cacheEntry).size
}
