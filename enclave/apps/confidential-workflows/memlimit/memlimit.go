// Package memlimit derives a static admission heuristic from enclave RAM.
// It is not an RSS limit: native compilation and Go allocations can exceed
// the per-worker budget. TODO: add cgroup resource containment separately.
package memlimit

const (
	// ReserveMB is memory set aside for everything other than concurrent
	// workflow executions: the Go runtime, the enclave server and host, TLS
	// buffers, and cached compressed artifacts.
	ReserveMB uint64 = 1024

	// Cold one-shot workers measured approximately 400 MiB peak RSS on the Go
	// SDK fixtures, versus 140 MiB warm. Budget for cold compilation, not just
	// the 128 MB Wasm linear-memory limit. Revalidate on target Nitro hardware.
	PerExecMB uint64 = 512

	// FallbackConcurrency is used when total memory can't be read (non-Linux
	// dev builds, or a sysinfo error). Conservative on purpose.
	FallbackConcurrency int64 = 2
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
