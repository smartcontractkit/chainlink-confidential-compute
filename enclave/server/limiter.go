package server

import "sync/atomic"

// executionLimiter bounds the number of concurrent app executions the server
// admits, so a burst can't exhaust the fixed enclave memory budget and wedge the
// VM. A nil slots channel means unbounded: the default, since only an entrypoint
// that knows the enclave's memory opts into a real limit (see
// WithMaxConcurrentExecutions). fake/local runs and tests stay unbounded.
type executionLimiter struct {
	slots chan struct{}
	// running counts admitted executions whether or not there is a bound, so the
	// occupancy reported on /memory is true for an unbounded server too. Counting
	// slots instead would report 0 while executions are in flight.
	running atomic.Int64
}

// newExecutionLimiter builds a limiter admitting at most max concurrent
// executions; max <= 0 means unbounded.
func newExecutionLimiter(max int64) *executionLimiter {
	if max <= 0 {
		return &executionLimiter{}
	}
	return &executionLimiter{slots: make(chan struct{}, max)}
}

// tryAcquire takes a slot without blocking, returning false if none is free. A
// nil limiter (or one built for an unbounded config) always admits.
func (l *executionLimiter) tryAcquire() bool {
	if l == nil {
		return true
	}
	if l.slots != nil {
		select {
		case l.slots <- struct{}{}:
		default:
			return false
		}
	}
	l.running.Add(1)
	return true
}

// release returns a slot taken by a successful tryAcquire. Call it exactly once
// per successful acquire (typically via defer).
func (l *executionLimiter) release() {
	if l == nil {
		return
	}
	l.running.Add(-1)
	if l.slots != nil {
		<-l.slots
	}
}

// capacity is the configured limit (0 = unbounded), for the rejection metric and
// for the limit the enclave reports to the host on /memory.
func (l *executionLimiter) capacity() int64 {
	if l == nil {
		return 0
	}
	return int64(cap(l.slots))
}

// inFlight is how many executions are currently admitted, bounded or not.
func (l *executionLimiter) inFlight() int64 {
	if l == nil {
		return 0
	}
	return l.running.Load()
}
