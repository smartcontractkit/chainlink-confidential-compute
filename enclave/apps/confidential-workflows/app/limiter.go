package app

// executionLimiter bounds the number of concurrent workflow executions so a
// burst can't exhaust the fixed enclave memory budget and wedge the VM. A nil
// slots channel means unbounded: the default, since only the nitro entrypoint
// opts into a real limit (derived from enclave memory). fake/local runs and
// tests stay unbounded.
type executionLimiter struct {
	slots chan struct{}
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
	if l == nil || l.slots == nil {
		return true
	}
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a slot taken by a successful tryAcquire. Call it exactly once
// per successful acquire (typically via defer).
func (l *executionLimiter) release() {
	if l == nil || l.slots == nil {
		return
	}
	<-l.slots
}

// capacity is the configured limit (0 = unbounded), for diagnostics.
func (l *executionLimiter) capacity() int {
	if l == nil {
		return 0
	}
	return cap(l.slots)
}
