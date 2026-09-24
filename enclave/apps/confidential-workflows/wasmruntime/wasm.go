// Package wasmruntime is the native Wasmtime boundary. Coordinators must not import it.
package wasmruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// Execute creates a chainlink-common WASM host module from the binary
// and runs the given ExecuteRequest.
// Production binaries are brotli-compressed; tests pass isCompressed=false.
//
// resolved contains the limits for this execution. The logger is
// also passed to host.ModuleConfig for WASM host diagnostics.
//
// timeout bounds the module run: the WASM host turns it into a wasmtime epoch
// deadline, which is the only thing that interrupts a guest spinning in pure
// compute (the ctx deadline alone unblocks host calls but not the guest). It
// surfaces as context.DeadlineExceeded. Non-positive leaves the host's own
// default (10 minutes) in place.
func Execute(ctx context.Context, lggr logger.Logger, resolved wasmlimits.Config, binary []byte, execReq *sdkpb.ExecuteRequest, isCompressed bool, helper host.ExecutionHelper, timeout time.Duration) (*sdkpb.ExecutionResult, error) {
	modCfg := newModuleConfig(resolved)
	defer func() {
		if err := closeModuleLimiters(modCfg); err != nil && lggr != nil {
			lggr.Warnf("closing WASM module limiters: %v", err)
		}
	}()

	modCfg.Logger = lggr
	modCfg.IsUncompressed = !isCompressed
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

func newModuleConfig(c wasmlimits.Config) *host.ModuleConfig {
	return &host.ModuleConfig{
		MemoryLimiter:                        limits.NewUpperBoundLimiter(c.Memory),
		MaxCompressedBinaryLimiter:           limits.NewUpperBoundLimiter(c.MaxCompressedBinary),
		MaxDecompressedBinaryLimiter:         limits.NewUpperBoundLimiter(c.MaxDecompressedBinary),
		MaxResponseSizeLimiter:               limits.NewUpperBoundLimiter(c.MaxResponseSize),
		PendingCallsLimiter:                  limits.WorkflowResourcePoolLimiter(c.PendingCalls),
		EnableUserMetricsLimiter:             limits.NewGateLimiter(c.EnableUserMetrics),
		MaxUserMetricPayloadLimiter:          limits.NewUpperBoundLimiter(c.MaxUserMetricPayload),
		MaxUserMetricNameLengthLimiter:       limits.NewUpperBoundLimiter(c.MaxUserMetricNameLength),
		MaxUserMetricLabelsPerMetricLimiter:  limits.NewUpperBoundLimiter(c.MaxUserMetricLabels),
		MaxUserMetricLabelValueLengthLimiter: limits.NewUpperBoundLimiter(c.MaxUserMetricLabelValueLen),
		MaxSubscriptionsLimiter:              limits.NewUpperBoundLimiter(c.MaxSubscriptions),
		MaxLogLenBytes:                       c.MaxLogLenBytes,
	}
}

func closeModuleLimiters(c *host.ModuleConfig) error {
	return services.CloseAll(c.MemoryLimiter, c.MaxCompressedBinaryLimiter, c.MaxDecompressedBinaryLimiter,
		c.MaxResponseSizeLimiter, c.PendingCallsLimiter, c.EnableUserMetricsLimiter, c.MaxUserMetricPayloadLimiter,
		c.MaxUserMetricNameLengthLimiter, c.MaxUserMetricLabelsPerMetricLimiter, c.MaxUserMetricLabelValueLengthLimiter, c.MaxSubscriptionsLimiter)
}
