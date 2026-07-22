// Package memlimit derives the enclave's concurrent-execution cap from its
// total memory, so a burst of workflow executions can't exhaust the fixed
// enclave memory budget and wedge the VM.
//
// The cap is (T - reserve) / perExec, where T is the enclave's total RAM read
// once at startup (see totalMemoryMB). It is a static, worst-case bound: it
// assumes every concurrent execution uses its full per-execution memory budget,
// so any workflow is safe regardless of what it actually allocates. We do not
// poll free memory at admission time (deliberately, to keep admission simple
// and side-channel-free).
package memlimit

const (
	// ReserveMB is memory set aside for everything other than concurrent
	// workflow executions: the Go runtime, the enclave server and host, TLS
	// buffers, and the WASM host's base working set. On the 2048 MiB staging
	// enclave this yields (2048-1024)/128 = 8, matching the previously
	// load-tested default, and it re-derives automatically if the enclave's
	// memory changes.
	ReserveMB uint64 = 1024

	// PerExecMB mirrors chainlink-common's defaultMinMemoryMBs, the per-module
	// WASM linear-memory floor a workflow execution can grow into. Keep in sync
	// if that default changes.
	PerExecMB uint64 = 128

	// FallbackConcurrency is used when total memory can't be read (non-Linux
	// dev builds, or a sysinfo error). Conservative on purpose.
	FallbackConcurrency int64 = 8
)

// Result is the derived concurrent-execution cap plus the inputs used to
// compute it, so the enclave can log how it arrived at the limit.
type Result struct {
	MaxConcurrent int64
	TotalMB       uint64
	ReserveMB     uint64
	PerExecMB     uint64
	Introspected  bool // false if total memory couldn't be read and we fell back
}

// Derive computes the concurrent-execution cap from the enclave's total memory,
// falling back to FallbackConcurrency when it can't be read.
func Derive() Result {
	r := Result{ReserveMB: ReserveMB, PerExecMB: PerExecMB}
	totalMB, err := totalMemoryMB()
	if err != nil || totalMB == 0 {
		r.MaxConcurrent = FallbackConcurrency
		return r
	}
	r.TotalMB = totalMB
	r.Introspected = true
	r.MaxConcurrent = concurrency(totalMB, ReserveMB, PerExecMB)
	return r
}

// concurrency returns how many perExecMB-sized executions fit in
// (totalMB - reserveMB), clamped to at least 1.
func concurrency(totalMB, reserveMB, perExecMB uint64) int64 {
	if perExecMB == 0 || totalMB <= reserveMB {
		return 1
	}
	n := int64((totalMB - reserveMB) / perExecMB)
	if n < 1 {
		return 1
	}
	return n
}
