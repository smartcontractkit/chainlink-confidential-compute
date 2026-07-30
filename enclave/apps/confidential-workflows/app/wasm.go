package app

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// executeWasm creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// hostLogger is plumbed through to host.ModuleConfig.Logger, where the WASM
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
func executeWasm(ctx context.Context, hostLogger logger.Logger, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
	modCfg := &host.ModuleConfig{
		Logger:         hostLogger,
		IsUncompressed: !isCompressed,
	}
	if timeout > 0 {
		modCfg.Timeout = &timeout
	}

	mod, err := host.NewModule(ctx, modCfg, binary)
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
