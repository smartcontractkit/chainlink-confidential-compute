package app

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"golang.org/x/sync/semaphore"
)

// executeWasm creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// lggr is plumbed through to host.ModuleConfig.Logger, where the WASM
// host runtime writes its own bookkeeping warnings/errors during module
// lifecycle (max-log-count or log-size limits exceeded, errors emitting
// user logs/metrics, lifecycle errors). Pass the app's shared logger so
// these diagnostics land alongside the rest of the enclave's output.
//
// timeout bounds the module run: the WASM host turns it into a wasmtime epoch
// deadline, which is the only thing that interrupts a guest spinning in pure
// compute (the ctx deadline alone unblocks host calls but not the guest). It
// surfaces as context.DeadlineExceeded. Non-positive leaves the host's own
// default (10 minutes) in place.
//
// compileSlot bounds simultaneous compilations while guests run concurrently
// (WorkflowSettings.MaxConcurrentCompilations slots). The timeout starts once
// this execution acquires a slot, so waiting doesn't consume the timeout, and
// a compilation that outlives it fails without starting the guest.
//
// emitter receives the compilation queue wait, compilation, and guest execution
// durations.
func executeWasm(ctx context.Context, lggr logger.Logger, emitter types.Emitter, compileSlot *semaphore.Weighted, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
	modCfg := &host.ModuleConfig{
		Logger:         lggr,
		IsUncompressed: !isCompressed,
	}
	if timeout > 0 {
		modCfg.Timeout = &timeout
	}

	execCtx, cancel := ctx, func() {}
	defer func() { cancel() }() // cancel is replaced once the timeout starts
	var mod host.ModuleV2
	queued := time.Now()
	err := func() error {
		if err := compileSlot.Acquire(ctx, 1); err != nil {
			return err
		}
		defer compileSlot.Release(1)
		started := time.Now()
		emitter.Emit("workflow_compilation_queue_wait", map[string]any{
			"duration_seconds": started.Sub(queued).Seconds(),
		})
		if timeout > 0 {
			execCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		compiled, compileErr := host.NewModule(execCtx, modCfg, binary)
		// Native compilation can't be interrupted, so the timeout may expire
		// meanwhile. Expiry decides the result; the log keeps any compile error.
		ctxErr := execCtx.Err()
		duration := time.Since(started)
		emitter.Emit("workflow_compilation", map[string]any{
			"success":          compileErr == nil && ctxErr == nil,
			"duration_seconds": duration.Seconds(),
		})
		if lggr != nil {
			lggr.Infow("workflow compilation completed", "queueDuration", started.Sub(queued), "duration", duration, "error", cmp.Or(compileErr, ctxErr))
		}
		if ctxErr != nil {
			if compiled != nil {
				compiled.Close() // free it before the next compilation; never start the guest
			}
			return ctxErr
		}
		if compileErr != nil {
			return compileErr
		}
		mod = compiled
		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("creating wasm module: %w", err)
	}
	mod.Start()
	defer mod.Close()

	guestStarted := time.Now()
	result, err := mod.Execute(execCtx, execReq, helper)
	emitter.Emit("workflow_guest_execution", map[string]any{
		"success":          err == nil,
		"duration_seconds": time.Since(guestStarted).Seconds(),
	})
	if err != nil {
		return nil, fmt.Errorf("executing wasm: %w", err)
	}

	return result, nil
}
