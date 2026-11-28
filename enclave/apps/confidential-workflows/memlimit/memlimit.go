// Package memlimit budgets executions and parallel compilation from guest RAM.
// These are static admission estimates, not RSS limits for arbitrary WASM.
// Free memory is deliberately not polled when admitting work.
package memlimit

import (
	"fmt"
	"math"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const (
	mib = 1024 * 1024

	// ReserveMB covers the Go runtime, enclave server, TLS buffers, the WASM
	// host's base working set, and the binary cache. The 768 MiB overhead estimate
	// is the previous 1024 MiB reserve minus the 256 MiB default cache, not an
	// independently measured baseline. Cache bytes are rounded up to MiB.
	ReserveMB uint64 = 768 + (types.DefaultMaxBinaryCacheBytes+mib-1)/mib
	// SafetyMB leaves headroom for allocator/GC variability and estimation error;
	// 128 MiB is a provisional margin, not a measured bound.
	SafetyMB uint64 = 128

	// PerExecMB is a best-effort allowance based on the host's linear-memory default:
	// https://github.com/smartcontractkit/chainlink-common/blob/f9f63cb65fce/pkg/workflows/wasm/host/module.go#L43-L45
	// Native/runtime and download overhead are not fully accounted for.
	// Wasmtime's resource limiter only covers instance allocations:
	// https://github.com/bytecodealliance/wasmtime/blob/ebe5e8df1f4e12c5fc2f5954926881d8d61367d8/crates/wasmtime/src/runtime/limits.rs#L21-L25
	// TODO: Recalibrate execution and compiler allowances with representative x86 workloads.
	PerExecMB uint64 = 128

	// Additional compiler/decompression allowance, retained even when the pool
	// is idle. Estimated from local x86 fixture screening, not a Wasmtime limit.
	// Recheck after Wasmtime changes.
	PerCompilationMB uint64 = 384
	// TargetCompilations is a policy ceiling for the reserved compile pool, not a
	// Wasmtime limit. Guest RAM or injected settings can lower actual concurrency.
	TargetCompilations uint64 = 8
)

// Result contains memory-derived admission limits and budget inputs for logging.
// These are not measured concurrency or workload percentiles.
// Compiling executions count toward both limits.
type Result struct {
	MaxConcurrentExecutions   int64
	MaxConcurrentCompilations int64
	TotalMB                   uint64
	ReserveMB                 uint64
	SafetyMB                  uint64
	PerExecMB                 uint64
	PerCompilationMB          uint64
}

// Derive reads total guest memory once, before either admission gate is built.
func Derive() (Result, error) {
	totalMB, err := totalMemoryMB()
	if err != nil {
		return Result{}, fmt.Errorf("reading guest memory: %w", err)
	}
	return ForMemory(totalMB)
}

// ForMemory reserves a compile pool before deriving execution capacity.
// The entire pool stays reserved even when settings select lower concurrency.
func ForMemory(totalMB uint64) (Result, error) {
	if totalMB < ReserveMB+SafetyMB+PerExecMB+PerCompilationMB {
		return Result{}, fmt.Errorf("guest memory %d MiB cannot fit one execution and compilation", totalMB)
	}
	available := totalMB - ReserveMB - SafetyMB
	// Each compilation needs an execution slot too, so fit paired execution and
	// compilation allowances up to the target. Reserve the compiler allowances,
	// then use the remaining memory for execution slots (including those compiling).
	// Integer division rounds both capacities down to fit the available budget.
	compilations := min(TargetCompilations, available/(PerExecMB+PerCompilationMB))
	executions := (available - compilations*PerCompilationMB) / PerExecMB
	if executions > math.MaxInt {
		return Result{}, fmt.Errorf("guest memory %d MiB yields an unsupported execution capacity", totalMB)
	}
	return Result{
		MaxConcurrentExecutions:   int64(executions),
		MaxConcurrentCompilations: int64(compilations),
		TotalMB:                   totalMB,
		ReserveMB:                 ReserveMB,
		SafetyMB:                  SafetyMB,
		PerExecMB:                 PerExecMB,
		PerCompilationMB:          PerCompilationMB,
	}, nil
}
