// Package wasmruntime compiles in the coordinator and executes serialized modules in workers.
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

// Execute loads only coordinator-produced native code. There is no source-Wasm
// fallback; source-size checks belong to the compiler.
func Execute(ctx context.Context, lggr logger.Logger, resolved wasmlimits.Config, path string, execReq *sdkpb.ExecuteRequest, helper host.ExecutionHelper) (*sdkpb.ExecutionResult, error) {
	cfg := newModuleConfig(resolved)
	defer closeLimiters(lggr, cfg)
	cfg.Logger = lggr
	started := time.Now()
	mod, err := host.NewModuleFromSerializedFile(ctx, cfg, path)
	RemoveArtifact(lggr, path)
	if err != nil {
		return nil, fmt.Errorf("loading wasm module: %w", err)
	}
	defer mod.Close()
	lggr.Infow("workflow artifact loaded", "duration", time.Since(started))
	if err := applyExecutionDeadline(ctx, cfg); err != nil {
		return nil, err
	}
	result, err := mod.Execute(ctx, execReq, helper)
	if err != nil {
		return nil, fmt.Errorf("executing wasm: %w", err)
	}
	return result, nil
}

func applyExecutionDeadline(ctx context.Context, cfg *host.ModuleConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	cfg.Timeout = &remaining
	prehookTimeout := min(*cfg.PrehookTimeout, remaining)
	cfg.PrehookTimeout = &prehookTimeout
	return nil
}

func closeLimiters(lggr logger.Logger, cfg *host.ModuleConfig) {
	if err := closeModuleLimiters(cfg); err != nil {
		lggr.Warnw("closing WASM module limiters", "error", err)
	}
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
