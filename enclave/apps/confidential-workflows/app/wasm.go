package app

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/wasmruntime"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// executeWasm creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// limiterSettings is the settings snapshot for this execution. The logger is
// also passed to host.ModuleConfig for WASM host diagnostics.
//
// Queue wait is excluded from timeout. The WASM host turns the timeout into a
// wasmtime epoch deadline, which is the only thing that interrupts a guest spinning in pure
// compute (the ctx deadline alone unblocks host calls but not the guest). It
// surfaces as context.DeadlineExceeded. Non-positive leaves the host's own
// default (10 minutes) in place.
func executeWasm(ctx context.Context, lggr logger.Logger, queue *wasmruntime.Queue, limiterSettings *limiterSettingsSnapshot, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
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
	var mod host.ModuleV2
	var cancel context.CancelFunc
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()
	queued := time.Now()
	err := queue.Run(ctx, func() error {
		started := time.Now()
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, timeout)
			modCfg.Timeout = &timeout
		}
		var err error
		mod, err = host.NewModule(ctx, modCfg, binary)
		if lggr != nil {
			lggr.Infow("workflow compilation completed", "queueDuration", started.Sub(queued), "duration", time.Since(started), "error", err)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("creating wasm module: %w", err)
	}
	mod.Start()
	defer mod.Close()

	result, err := mod.Execute(ctx, execReq, helper)
	if err != nil {
		return nil, fmt.Errorf("executing wasm: %w", err)
	}

	return result, nil
}
