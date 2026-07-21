package app

import (
	"sync"
	"testing"
)

func TestExecutionLimiter_Unbounded(t *testing.T) {
	l := newExecutionLimiter(0)
	for i := 0; i < 100; i++ {
		if !l.tryAcquire() {
			t.Fatalf("unbounded limiter rejected acquire %d", i)
		}
	}
	if got := l.capacity(); got != 0 {
		t.Fatalf("capacity() = %d, want 0 for unbounded", got)
	}
}

func TestExecutionLimiter_Bounded(t *testing.T) {
	l := newExecutionLimiter(2)
	if !l.tryAcquire() || !l.tryAcquire() {
		t.Fatal("limiter rejected an acquire within capacity")
	}
	if l.tryAcquire() {
		t.Fatal("limiter admitted an acquire beyond capacity")
	}
	l.release()
	if !l.tryAcquire() {
		t.Fatal("limiter did not free a slot on release")
	}
	if l.tryAcquire() {
		t.Fatal("limiter admitted beyond capacity after a single release")
	}
	if got := l.capacity(); got != 2 {
		t.Fatalf("capacity() = %d, want 2", got)
	}
}

// Exercised under -race: concurrent acquire/release must not admit more than the
// limit at once.
func TestExecutionLimiter_ConcurrentNeverExceeds(t *testing.T) {
	const limit = 4
	l := newExecutionLimiter(limit)

	var mu sync.Mutex
	inFlight, maxSeen := 0, 0

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !l.tryAcquire() {
				return
			}
			defer l.release()
			mu.Lock()
			inFlight++
			if inFlight > maxSeen {
				maxSeen = inFlight
			}
			mu.Unlock()
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
	}
	wg.Wait()
	if maxSeen > limit {
		t.Fatalf("observed %d concurrent holders, limit is %d", maxSeen, limit)
	}
}
