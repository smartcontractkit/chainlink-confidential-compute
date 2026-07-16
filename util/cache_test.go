package util

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func createKey(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func TestCacheBasicOperations(t *testing.T) {
	ttl := 100 * time.Millisecond
	gcInterval := 50 * time.Millisecond
	cache := NewCache[string](&ttl, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")
	nonExistentKey := createKey("nonexistent")

	cache.Set(key1, "value1", nil)
	cache.Set(key2, "value2", nil)

	val1, exists1 := cache.Get(key1)
	if !exists1 {
		t.Error("Expected key1 to exist")
	}
	if val1 != "value1" {
		t.Errorf("Expected value1, got %s", val1)
	}

	val2, exists2 := cache.Get(key2)
	if !exists2 {
		t.Error("Expected key2 to exist")
	}
	if val2 != "value2" {
		t.Errorf("Expected value2, got %s", val2)
	}

	val3, exists3 := cache.Get(nonExistentKey)
	if exists3 {
		t.Error("Expected nonexistent key to not exist")
	}
	if val3 != "" {
		t.Errorf("Expected empty string, got %s", val3)
	}

	if cache.Size() != 2 {
		t.Errorf("Expected cache size to be 2, got %d", cache.Size())
	}

	keys := cache.Keys()
	if len(keys) != 2 {
		t.Errorf("Expected keys length to be 2, got %d", len(keys))
	}
}

func TestCacheExpiration(t *testing.T) {
	ttl := 50 * time.Millisecond
	gcInterval := 100 * time.Millisecond
	cache := NewCache[int](&ttl, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	cache.Set(key1, 100, nil)

	val1, exists1 := cache.Get(key1)
	if !exists1 {
		t.Error("Expected key1 to exist immediately after setting")
	}
	if val1 != 100 {
		t.Errorf("Expected 100, got %d", val1)
	}

	time.Sleep(75 * time.Millisecond)

	_, exists2 := cache.Get(key1)
	if exists2 {
		t.Error("Expected key1 to expire after TTL")
	}
}

func TestCacheDelete(t *testing.T) {
	ttl := 100 * time.Millisecond
	gcInterval := 50 * time.Millisecond
	cache := NewCache[string](&ttl, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")

	cache.Set(key1, "value1", nil)
	cache.Set(key2, "value2", nil)

	if cache.Size() != 2 {
		t.Errorf("Expected size to be 2, got %d", cache.Size())
	}

	cache.Delete(key1)

	val1, exists1 := cache.Get(key1)
	if exists1 {
		t.Error("Expected key1 to be deleted")
	}
	if val1 != "" {
		t.Errorf("Expected empty string after delete, got %s", val1)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected size to be 1 after delete, got %d", cache.Size())
	}

	keys := cache.Keys()
	if len(keys) != 1 {
		t.Errorf("Expected keys to contain only one key")
	}
}

func TestCacheGarbageCollection(t *testing.T) {
	ttl := 50 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&ttl, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")

	cache.Set(key1, "value1", nil)

	time.Sleep(100 * time.Millisecond)

	key2 := createKey("key2")
	cache.Set(key2, "value2", nil)

	removed := cache.garbageCollect()
	if removed != 1 {
		t.Errorf("Expected 1 item to be removed by GC, got %d", removed)
	}

	_, exists1 := cache.Get(key1)
	if exists1 {
		t.Error("Expected key1 to be garbage collected")
	}

	val2, exists2 := cache.Get(key2)
	if !exists2 {
		t.Error("Expected key2 to still exist")
	}
	if val2 != "value2" {
		t.Errorf("Expected value2, got %s", val2)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected size to be 1 after GC, got %d", cache.Size())
	}
}

func TestCacheWithStructs(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}

	ttl := 100 * time.Millisecond
	gcInterval := 50 * time.Millisecond
	cache := NewCache[Person](&ttl, &gcInterval)
	defer cache.Stop()

	person1 := Person{Name: "Alice", Age: 30}
	person2 := Person{Name: "Bob", Age: 25}

	key1 := createKey("person1")
	key2 := createKey("person2")

	cache.Set(key1, person1, nil)
	cache.Set(key2, person2, nil)

	p1, exists1 := cache.Get(key1)
	if !exists1 {
		t.Error("Expected person1 to exist")
	}
	if p1.Name != "Alice" || p1.Age != 30 {
		t.Errorf("Expected {Alice, 30}, got {%s, %d}", p1.Name, p1.Age)
	}

	p2, exists2 := cache.Get(key2)
	if !exists2 {
		t.Error("Expected person2 to exist")
	}
	if p2.Name != "Bob" || p2.Age != 25 {
		t.Errorf("Expected {Bob, 25}, got {%s, %d}", p2.Name, p2.Age)
	}
}

func TestAutomaticGarbageCollection(t *testing.T) {
	ttl := 50 * time.Millisecond
	gcInterval := 60 * time.Millisecond
	cache := NewCache[string](&ttl, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")

	cache.Set(key1, "value1", nil)
	cache.Set(key2, "value2", nil)

	if cache.Size() != 2 {
		t.Errorf("Expected size to be 2, got %d", cache.Size())
	}

	time.Sleep(150 * time.Millisecond) // Wait for automatic GC to run

	if cache.Size() != 0 {
		t.Errorf("Expected all items to be automatically garbage collected, got %d items", cache.Size())
	}
}

func TestCachePerItemTTL(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 50 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")

	// Set key1 with default TTL (100ms)
	cache.Set(key1, "value1", nil)

	// Set key2 with custom short TTL (50ms)
	ttl := 50 * time.Millisecond
	cache.Set(key2, "value2", &ttl)

	// Both should exist immediately
	_, exists1 := cache.Get(key1)
	_, exists2 := cache.Get(key2)
	if !exists1 || !exists2 {
		t.Error("Expected both keys to exist immediately after setting")
	}

	// Wait 60ms - key2 should expire but key1 should still exist
	time.Sleep(60 * time.Millisecond)

	val1, exists1 := cache.Get(key1)
	_, exists2 = cache.Get(key2)

	if !exists1 {
		t.Error("Expected key1 to still exist after 60ms (TTL=100ms)")
	}
	if val1 != "value1" {
		t.Errorf("Expected value1, got %s", val1)
	}
	if exists2 {
		t.Error("Expected key2 to expire after 60ms (TTL=50ms)")
	}

	// Wait another 50ms - key1 should now expire too
	time.Sleep(50 * time.Millisecond)

	_, exists1 = cache.Get(key1)
	if exists1 {
		t.Error("Expected key1 to expire after 110ms total")
	}
}

// TestCachePerItemTTLLongerThanDefault tests items with TTL longer than default
func TestCachePerItemTTLLongerThanDefault(t *testing.T) {
	defaultTTL := 50 * time.Millisecond
	gcInterval := 100 * time.Millisecond
	cache := NewCache[int](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")

	// Set key1 with default TTL (50ms)
	cache.Set(key1, 100, nil)

	// Set key2 with custom long TTL (150ms)
	ttl := 150 * time.Millisecond

	cache.Set(key2, 200, &ttl)

	// Wait 70ms - key1 should expire but key2 should still exist
	time.Sleep(70 * time.Millisecond)

	_, exists1 := cache.Get(key1)
	val2, exists2 := cache.Get(key2)

	if exists1 {
		t.Error("Expected key1 to expire after 70ms (TTL=50ms)")
	}
	if !exists2 {
		t.Error("Expected key2 to still exist after 70ms (TTL=150ms)")
	}
	if val2 != 200 {
		t.Errorf("Expected 200, got %d", val2)
	}

	// Wait another 100ms - key2 should now expire
	time.Sleep(100 * time.Millisecond)

	_, exists2 = cache.Get(key2)
	if exists2 {
		t.Error("Expected key2 to expire after 170ms total")
	}
}

// TestCachePerItemTTLMultipleItems tests multiple items with different TTLs
func TestCachePerItemTTLMultipleItems(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")
	key3 := createKey("key3")
	key4 := createKey("key4")

	// Set items with different TTLs
	ttl := 25 * time.Millisecond
	cache.Set(key1, "value1", &ttl) // 25ms
	ttl = 50 * time.Millisecond
	cache.Set(key2, "value2", &ttl) // 50ms
	ttl = 75 * time.Millisecond
	cache.Set(key3, "value3", &ttl) // 75ms
	cache.Set(key4, "value4", nil)  // 100ms (default)

	if cache.Size() != 4 {
		t.Errorf("Expected size 4, got %d", cache.Size())
	}

	// After 30ms: key1 should be expired
	time.Sleep(30 * time.Millisecond)
	_, e1 := cache.Get(key1)
	_, e2 := cache.Get(key2)
	_, e3 := cache.Get(key3)
	_, e4 := cache.Get(key4)

	if e1 {
		t.Error("Expected key1 to be expired after 40ms")
	}
	if !e2 || !e3 || !e4 {
		t.Error("Expected key2, key3, key4 to still exist after 40ms")
	}

	// After 60ms total: key2 should be expired
	time.Sleep(30 * time.Millisecond)
	_, e2 = cache.Get(key2)
	_, e3 = cache.Get(key3)
	_, e4 = cache.Get(key4)

	if e2 {
		t.Error("Expected key2 to be expired after 70ms")
	}
	if !e3 || !e4 {
		t.Error("Expected key3, key4 to still exist after 70ms")
	}

	// After 90ms total: key3 should be expired
	time.Sleep(30 * time.Millisecond)
	_, e3 = cache.Get(key3)
	_, e4 = cache.Get(key4)

	if e3 {
		t.Error("Expected key3 to be expired after 100ms")
	}
	if !e4 {
		t.Error("Expected key4 to still exist after 100ms")
	}

	// After 110ms total: all should be expired
	time.Sleep(20 * time.Millisecond)
	_, e4 = cache.Get(key4)

	if e4 {
		t.Error("Expected key4 to be expired after 110ms")
	}
}

// TestCachePerItemTTLGarbageCollection tests that GC respects per-item TTLs
func TestCachePerItemTTLGarbageCollection(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")
	key3 := createKey("key3")

	ttl := 30 * time.Millisecond
	cache.Set(key1, "value1", &ttl)
	ttl = 60 * time.Millisecond
	cache.Set(key2, "value2", &ttl)
	ttl = 90 * time.Millisecond
	cache.Set(key3, "value3", &ttl)

	// Wait for all to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger GC
	removed := cache.garbageCollect()

	if removed != 3 {
		t.Errorf("Expected 3 items to be removed by GC, got %d", removed)
	}

	if cache.Size() != 0 {
		t.Errorf("Expected cache to be empty after GC, got size %d", cache.Size())
	}
}

// TestCachePerItemTTLOverwrite tests that overwriting a key updates its TTL
func TestCachePerItemTTLOverwrite(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")

	// Set with short TTL
	ttl := 50 * time.Millisecond
	cache.Set(key1, "value1", &ttl)

	// Wait 30ms
	time.Sleep(30 * time.Millisecond)

	// Overwrite with longer TTL
	ttl = 100 * time.Millisecond
	cache.Set(key1, "value2", &ttl)

	// Wait another 40ms (70ms total from first set, 40ms from second set)
	time.Sleep(40 * time.Millisecond)

	// Should still exist because we reset the TTL
	val, exists := cache.Get(key1)
	if !exists {
		t.Error("Expected key1 to still exist after overwrite with longer TTL")
	}
	if val != "value2" {
		t.Errorf("Expected value2, got %s", val)
	}

	// Wait another 70ms (should now expire)
	time.Sleep(70 * time.Millisecond)

	_, exists = cache.Get(key1)
	if exists {
		t.Error("Expected key1 to eventually expire")
	}
}

// TestCachePerItemTTLZeroDuration tests edge case of zero duration TTL
func TestCachePerItemTTLZeroDuration(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")

	// Set with zero TTL - should expire immediately
	ttl := 0 * time.Millisecond
	cache.Set(key1, "value1", &ttl)

	// Should not exist even immediately
	_, exists := cache.Get(key1)
	if exists {
		t.Error("Expected key with zero TTL to be immediately expired")
	}
}

// TestCacheFlush tests the new Flush functionality
func TestCacheFlush(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	gcInterval := 200 * time.Millisecond
	cache := NewCache[string](&defaultTTL, &gcInterval)
	defer cache.Stop()

	key1 := createKey("key1")
	key2 := createKey("key2")
	key3 := createKey("key3")

	ttl := 50 * time.Millisecond
	cache.Set(key1, "value1", &ttl)
	cache.Set(key2, "value2", nil)
	ttl = 150 * time.Millisecond
	cache.Set(key3, "value3", &ttl)

	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}

	// Flush all items
	cache.Flush()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after flush, got %d", cache.Size())
	}

	_, e1 := cache.Get(key1)
	_, e2 := cache.Get(key2)
	_, e3 := cache.Get(key3)

	if e1 || e2 || e3 {
		t.Error("Expected all keys to be removed after flush")
	}

	keys := cache.Keys()
	if len(keys) != 0 {
		t.Errorf("Expected empty keys list after flush, got %d keys", len(keys))
	}
}

func TestBoundedCacheEvictsOldestAtCap(t *testing.T) {
	ttl := time.Minute
	cache := NewBoundedCache[int](&ttl, nil, 10)
	defer cache.Stop()

	for i := 0; i < 11; i++ {
		cache.Set(createKey(fmt.Sprintf("key%d", i)), i, nil)
	}

	if size := cache.Size(); size > 10 {
		t.Errorf("Expected size <= 10 after overflow, got %d", size)
	}
	// Overflow evicts oldest-inserted entries first.
	if _, exists := cache.Get(createKey("key0")); exists {
		t.Error("Expected oldest entry key0 to be evicted")
	}
	if _, exists := cache.Get(createKey("key10")); !exists {
		t.Error("Expected newest entry key10 to survive eviction")
	}
}

func TestBoundedCacheFloodStaysBounded(t *testing.T) {
	ttl := time.Minute
	cache := NewBoundedCache[struct{}](&ttl, nil, 100)
	defer cache.Stop()

	for i := 0; i < 10_000; i++ {
		cache.Set(createKey(fmt.Sprintf("flood%d", i)), struct{}{}, nil)
	}

	if size := cache.Size(); size > 100 {
		t.Errorf("Expected size <= 100 under flood, got %d", size)
	}
	if len(cache.keyList) != cache.Size() {
		t.Errorf("keyList (%d) and items (%d) out of sync", len(cache.keyList), cache.Size())
	}
}

func TestBoundedCacheReSetDoesNotGrow(t *testing.T) {
	ttl := time.Minute
	cache := NewBoundedCache[int](&ttl, nil, 5)
	defer cache.Stop()

	key := createKey("same-key")
	for i := 0; i < 20; i++ {
		cache.Set(key, i, nil)
	}

	if size := cache.Size(); size != 1 {
		t.Errorf("Expected size 1 after re-setting one key, got %d", size)
	}
	if val, _ := cache.Get(key); val != 19 {
		t.Errorf("Expected latest value 19, got %d", val)
	}
}

func TestCacheGetOrSet(t *testing.T) {
	ttl := time.Minute
	cache := NewCache[int](&ttl, nil)
	defer cache.Stop()

	key := createKey("key")
	// First writer wins.
	if val, loaded := cache.GetOrSet(key, 1, nil); loaded || val != 1 {
		t.Errorf("Expected (1, false) on first GetOrSet, got (%d, %v)", val, loaded)
	}
	if val, loaded := cache.GetOrSet(key, 2, nil); !loaded || val != 1 {
		t.Errorf("Expected (1, true) on second GetOrSet, got (%d, %v)", val, loaded)
	}
}

func TestCacheGetOrSetExpiredEntry(t *testing.T) {
	shortTTL := 10 * time.Millisecond
	cache := NewCache[int](&shortTTL, nil)
	defer cache.Stop()

	key := createKey("key")
	cache.Set(key, 1, nil)
	time.Sleep(2 * shortTTL)

	// An expired entry is replaced, not returned.
	if val, loaded := cache.GetOrSet(key, 2, nil); loaded || val != 2 {
		t.Errorf("Expected (2, false) after expiry, got (%d, %v)", val, loaded)
	}
}

func TestBoundedCacheGetOrSetEvictsAtCap(t *testing.T) {
	ttl := time.Minute
	cache := NewBoundedCache[int](&ttl, nil, 10)
	defer cache.Stop()

	for i := 0; i < 11; i++ {
		cache.GetOrSet(createKey(fmt.Sprintf("key%d", i)), i, nil)
	}

	if size := cache.Size(); size > 10 {
		t.Errorf("Expected size <= 10 after overflow, got %d", size)
	}
	if _, exists := cache.Get(createKey("key0")); exists {
		t.Error("Expected oldest entry key0 to be evicted")
	}
}

func TestUnboundedCacheByDefault(t *testing.T) {
	ttl := time.Minute
	cache := NewCache[int](&ttl, nil)
	defer cache.Stop()

	for i := 0; i < 50; i++ {
		cache.Set(createKey(fmt.Sprintf("key%d", i)), i, nil)
	}

	if size := cache.Size(); size != 50 {
		t.Errorf("Expected all 50 entries in unbounded cache, got %d", size)
	}
}
