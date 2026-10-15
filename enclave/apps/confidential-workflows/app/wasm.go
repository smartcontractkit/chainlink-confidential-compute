package app

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"golang.org/x/sync/semaphore"
)

// executeWasm creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// limiterSettings is the settings snapshot for this execution. The logger is
// also passed to host.ModuleConfig for WASM host diagnostics.
//
// timeout bounds the module run: the WASM host turns it into a wasmtime epoch
// deadline, which is the only thing that interrupts a guest spinning in pure
// compute (the ctx deadline alone unblocks host calls but not the guest). It
// surfaces as context.DeadlineExceeded. Non-positive leaves the host's own
// default (10 minutes) in place.
//
// compileSlot serializes compilation while guests run concurrently. The
// timeout starts once this execution acquires it, so waiting doesn't consume
// the timeout, and a compilation that outlives it fails without starting the
// guest.
func executeWasm(ctx context.Context, lggr logger.Logger, compileSlot *semaphore.Weighted, limiterSettings *limiterSettingsSnapshot, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
	moduleLimiters := newWASMModuleLimiters(ctx, lggr, limiterSettings)
	defer func() {
		if err := moduleLimiters.Close(); err != nil && lggr != nil {
			lggr.Warnf("closing WASM module limiters: %v", err)
		}
	}()

	modCfg := &host.ModuleConfig{
		Logger:         lggr,
		IsUncompressed: !isCompressed,
	}
	moduleLimiters.apply(modCfg)
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
		if timeout > 0 {
			execCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		compiled, compileErr := host.NewModule(execCtx, modCfg, binary)
		// Native compilation can't be interrupted, so the timeout may expire
		// meanwhile. Expiry decides the result; the log keeps any compile error.
		ctxErr := execCtx.Err()
		if lggr != nil {
			lggr.Infow("workflow compilation completed", "queueDuration", started.Sub(queued), "duration", time.Since(started), "error", cmp.Or(compileErr, ctxErr))
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

	result, err := mod.Execute(execCtx, execReq, helper)
	if err != nil {
		return nil, fmt.Errorf("executing wasm: %w", err)
	}

	return result, nil
}
