package binaryfetch

import (
	"container/list"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Cache is a size-bounded LRU index over a Store. It owns the eviction policy
// and the byte accounting; the Store owns where the bytes actually live, so the
// same policy applies to the enclave's in-memory cache and the host's on-disk
// one.
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
	evicted := c.evictToFitLocked(0)
	c.mu.Unlock()
	for _, key := range evicted {
		store.Delete(key)
	}
	return c
}

// Get returns the cached binary for key, promoting it to most recent.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	el, ok := c.items[key]
	if ok {
		c.evictList.MoveToFront(el)
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}

	value, found := c.store.Get(key)
	if !found {
		// The store lost the entry behind our back (disk cache cleared, file
		// removed). Drop the index entry so accounting stays truthful.
		c.mu.Lock()
		c.removeLocked(key)
		c.mu.Unlock()
		return nil, false
	}
	return value, true
}

// Put stores value under key, evicting least-recently-used entries to stay
// within the byte bound. A value larger than the whole bound is not cached.
//
// The store write happens outside the lock so slow disk I/O doesn't block other
// cache users, so the incoming bytes are *reserved* in cacheBytes before
// unlocking. Without that reservation two concurrent Puts for different keys
// would both see the same free space, both evict to fit, and both publish --
// leaving the cache over its bound.
func (c *Cache) Put(key string, value []byte) {
	c.mu.Lock()
	if len(value) > c.maxCacheBytes {
		maxCacheBytes := c.maxCacheBytes
		c.mu.Unlock()
		c.logger.Warnf("binary (%d bytes) exceeds cache bound (%d bytes), not caching", len(value), maxCacheBytes)
		return
	}
	if el, ok := c.items[key]; ok {
		c.evictList.MoveToFront(el)
		c.mu.Unlock()
		return
	}
	evicted := c.evictToFitLocked(len(value))
	// Reserve the space now. The entry has no list element yet, so these bytes
	// are counted but cannot themselves be evicted until it is published.
	c.cacheBytes += len(value)
	c.mu.Unlock()

	for _, key := range evicted {
		c.store.Delete(key)
	}

	if err := c.store.Put(key, value); err != nil {
		// A cache write failure is not fatal: the caller already holds the
		// bytes, so release the reservation, log and continue uncached rather
		// than failing the request.
		c.releaseReservation(len(value))
		c.logger.Warnf("caching binary %q: %v", key, err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[key]; ok {
		// Another goroutine published the same key while we were writing; its
		// entry already accounts for the bytes, so drop our reservation.
		c.cacheBytes -= len(value)
		return
	}
	// Publish against the reservation taken above: the bytes are already in
	// cacheBytes, so only the index entry is added here.
	el := c.evictList.PushFront(&cacheEntry{key: key, size: len(value)})
	c.items[key] = el
}

// releaseReservation gives back bytes reserved by Put when the entry is never
// published.
func (c *Cache) releaseReservation(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheBytes -= size
}

// SetMaxCacheBytes updates the cache size bound, evicting least-recently-used
// entries if the new bound is smaller than the current usage. A non-positive
// value is ignored.
func (c *Cache) SetMaxCacheBytes(maxCacheBytes int) {
	if maxCacheBytes <= 0 {
		return
	}
	c.mu.Lock()
	c.maxCacheBytes = maxCacheBytes
	evicted := c.evictToFitLocked(0)
	c.mu.Unlock()

	for _, key := range evicted {
		c.store.Delete(key)
	}
}

// Bytes returns the total size of the cached entries.
func (c *Cache) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cacheBytes
}

// evictToFitLocked drops least-recently-used entries until incoming more bytes
// fits within the bound, returning the keys to delete from the store. Callers
// must hold c.mu; the returned keys are deleted outside the lock so store I/O
// never blocks other cache users.
func (c *Cache) evictToFitLocked(incoming int) []string {
	var evicted []string
	for c.cacheBytes+incoming > c.maxCacheBytes && c.evictList.Len() > 0 {
		oldest := c.evictList.Back()
		entry := oldest.Value.(*cacheEntry)
		c.evictList.Remove(oldest)
		delete(c.items, entry.key)
		c.cacheBytes -= entry.size
		evicted = append(evicted, entry.key)
	}
	return evicted
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
