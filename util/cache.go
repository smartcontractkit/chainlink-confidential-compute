package util

import (
	"sync"
	"time"

	"github.com/smartcontractkit/confidential-compute/types"
)

var (
	defaultTTL        = types.DefaultCacheTTL
	defaultGCInterval = 1 * time.Minute
)

// evictionBatchDivisor sets the fraction of a bounded cache's capacity
// (1/evictionBatchDivisor) evicted in one batch when the cap is exceeded.
const evictionBatchDivisor = 10

type CacheItem[T any] struct {
	Value        T
	CreationTime time.Time
	TimeToLive   time.Duration
}

type Cache[T any] struct {
	items      map[[32]byte]CacheItem[T]
	keyList    [][32]byte
	mu         sync.RWMutex
	stopGC     chan struct{}
	timeToLive time.Duration
	gcInterval time.Duration
	maxEntries int // 0 means unbounded
}

// Concurrency-safe generic cache with configurable TTL & garbage collection interval.
// Supported functions: Set(), Get(), Delete(), Keys(), Size(), TimeToLive(), Flush(), Stop()
func NewCache[T any](ttl *time.Duration, gcInterval *time.Duration) *Cache[T] {
	return NewBoundedCache[T](ttl, gcInterval, 0)
}

// NewBoundedCache is NewCache with a cap on the number of entries. Once the
// cache holds maxEntries entries, Set evicts the oldest-inserted entries.
// maxEntries <= 0 means unbounded.
func NewBoundedCache[T any](ttl *time.Duration, gcInterval *time.Duration, maxEntries int) *Cache[T] {
	if ttl == nil {
		ttl = &defaultTTL
	}
	if gcInterval == nil {
		gcInterval = &defaultGCInterval
	}
	cache := &Cache[T]{
		items:      make(map[[32]byte]CacheItem[T]),
		keyList:    make([][32]byte, 0),
		stopGC:     make(chan struct{}),
		timeToLive: *ttl,
		gcInterval: *gcInterval,
		maxEntries: maxEntries,
	}
	go cache.startGCTicker()
	return cache
}

func (c *Cache[T]) Set(key [32]byte, value T, ttl *time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value, ttl)
}

// GetOrSet returns the existing unexpired value for key (loaded=true), or
// stores value and returns it (loaded=false). The first writer for a key
// wins. Storing may evict the oldest-inserted entries to stay within the cap.
func (c *Cache[T]) GetOrSet(key [32]byte, value T, ttl *time.Duration) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists && time.Since(item.CreationTime) <= item.TimeToLive {
		return item.Value, true
	}
	c.setLocked(key, value, ttl)
	return value, false
}

// setLocked stores value under key. Caller must hold c.mu.
func (c *Cache[T]) setLocked(key [32]byte, value T, ttl *time.Duration) {
	itemTTL := c.timeToLive
	if ttl != nil {
		itemTTL = *ttl
	}

	item := CacheItem[T]{
		Value:        value,
		CreationTime: time.Now(),
		TimeToLive:   itemTTL,
	}

	_, exists := c.items[key]
	c.items[key] = item

	if !exists {
		c.keyList = append(c.keyList, key)
	}

	if c.maxEntries > 0 && len(c.keyList) > c.maxEntries {
		// Evict the oldest batch (at least the overflow) in one pass to
		// amortize the slice shift. A re-Set key keeps its original position
		// in keyList and may be evicted with its refreshed value.
		evict := len(c.keyList) - c.maxEntries + c.maxEntries/evictionBatchDivisor
		if evict > len(c.keyList) {
			evict = len(c.keyList)
		}
		for _, k := range c.keyList[:evict] {
			delete(c.items, k)
		}
		c.keyList = append(make([][32]byte, 0, c.maxEntries+1), c.keyList[evict:]...)
	}
}

func (c *Cache[T]) Get(key [32]byte) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		var zeroValue T
		return zeroValue, false
	}

	if time.Since(item.CreationTime) > item.TimeToLive {
		var zeroValue T
		return zeroValue, false
	}

	return item.Value, true
}

func (c *Cache[T]) Delete(key [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)

	for i, k := range c.keyList {
		if k == key {
			c.keyList = append(c.keyList[:i], c.keyList[i+1:]...)
			break
		}
	}
}

func (c *Cache[T]) Keys() [][32]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([][32]byte, len(c.keyList))
	copy(keys, c.keyList)
	return keys
}

func (c *Cache[T]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache[T]) TimeToLive() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeToLive
}

func (c *Cache[T]) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[[32]byte]CacheItem[T])
	c.keyList = make([][32]byte, 0)
}

func (c *Cache[T]) Stop() {
	close(c.stopGC)
}

func (c *Cache[T]) startGCTicker() {
	ticker := time.NewTicker(c.gcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.garbageCollect()
		case <-c.stopGC:
			return
		}
	}
}

func (c *Cache[T]) garbageCollect() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	now := time.Now()

	for i := len(c.keyList) - 1; i >= 0; i-- {
		key := c.keyList[i]
		item, exists := c.items[key]
		if !exists || now.Sub(item.CreationTime) > item.TimeToLive {
			delete(c.items, key)
			c.keyList = append(c.keyList[:i], c.keyList[i+1:]...)
			removed++
		}
	}

	return removed
}
