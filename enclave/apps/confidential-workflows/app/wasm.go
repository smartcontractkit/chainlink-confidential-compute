package app

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// executeWasm creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// limitsFactory supplies the settings source and logger for the module's
// caller-owned limiters. Its logger is also passed to host.ModuleConfig so
// WASM host diagnostics land alongside the rest of the enclave's output.
//
// timeout bounds the module run: the WASM host turns it into a wasmtime epoch
// deadline, which is the only thing that interrupts a guest spinning in pure
// compute (the ctx deadline alone unblocks host calls but not the guest). It
// surfaces as context.DeadlineExceeded. Non-positive leaves the host's own
// default (10 minutes) in place.
func executeWasm(ctx context.Context, limitsFactory limits.Factory, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
	moduleLimiters, err := newWASMModuleLimiters(limitsFactory)
	if err != nil {
		return nil, fmt.Errorf("creating WASM module limiters: %w", err)
	}
	defer func() {
		if err := moduleLimiters.Close(); err != nil && limitsFactory.Logger != nil {
			limitsFactory.Logger.Warnf("closing WASM module limiters: %v", err)
		}
	}()

	modCfg := &host.ModuleConfig{
		Logger:         limitsFactory.Logger,
		IsUncompressed: !isCompressed,
	}
	moduleLimiters.apply(modCfg)
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
