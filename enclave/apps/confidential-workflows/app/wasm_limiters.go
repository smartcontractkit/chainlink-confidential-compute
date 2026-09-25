package app

import (
	"context"
	"fmt"
	"math"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
)

type wasmModuleLimiters struct {
	memory                     limits.BoundLimiter[config.Size]
	maxCompressedBinary        limits.BoundLimiter[config.Size]
	maxDecompressedBinary      limits.BoundLimiter[config.Size]
	maxResponseSize            limits.BoundLimiter[config.Size]
	pendingCalls               limits.ResourcePoolLimiter[int]
	enableUserMetrics          limits.GateLimiter
	maxUserMetricPayload       limits.BoundLimiter[config.Size]
	maxUserMetricNameLength    limits.BoundLimiter[int]
	maxUserMetricLabels        limits.BoundLimiter[int]
	maxUserMetricLabelValueLen limits.BoundLimiter[int]
	maxSubscriptions           limits.BoundLimiter[int]
	maxLogLenBytes             uint32
}

func newWASMModuleLimiters(ctx context.Context, lggr logger.Logger, snapshot *limiterSettingsSnapshot) *wasmModuleLimiters {
	cfg := cresettings.Default.PerWorkflow
	memory := resolveWASMSetting(ctx, lggr, snapshot, cfg.WASMMemoryLimit)
	if memory < config.MByte {
		snapshot.logFallback(lggr, cfg.WASMMemoryLimit.Key, fmt.Errorf("WASM memory limit must be at least 1 MB: %s", memory))
		memory = cfg.WASMMemoryLimit.DefaultValue
	}
	logLine := resolveWASMSetting(ctx, lggr, snapshot, cfg.LogLineLimit)
	if err := validateMaxLogLenBytes(logLine); err != nil {
		snapshot.logFallback(lggr, cfg.LogLineLimit.Key, err)
		logLine = cfg.LogLineLimit.DefaultValue
	}
	compressed := resolveWASMSetting(ctx, lggr, snapshot, cfg.WASMCompressedBinarySizeLimit)
	decompressed := resolveWASMSetting(ctx, lggr, snapshot, cfg.WASMBinarySizeLimit)
	response := resolveWASMSetting(ctx, lggr, snapshot, cfg.ExecutionResponseLimit)
	pendingCalls := resolveWASMSetting(ctx, lggr, snapshot, cfg.CapabilityConcurrencyLimit)
	userMetrics := resolveWASMSetting(ctx, lggr, snapshot, cfg.UserMetricEnabled)
	metricPayload := resolveWASMSetting(ctx, lggr, snapshot, cfg.UserMetricPayloadLimit)
	metricName := resolveWASMSetting(ctx, lggr, snapshot, cfg.UserMetricNameLengthLimit)
	metricLabels := resolveWASMSetting(ctx, lggr, snapshot, cfg.UserMetricLabelsPerMetric)
	metricLabelValue := resolveWASMSetting(ctx, lggr, snapshot, cfg.UserMetricLabelValueLength)
	subscriptions := resolveWASMSetting(ctx, lggr, snapshot, cresettings.Default.WASMPollOneoffSubscriptionLimit)

	return &wasmModuleLimiters{
		memory:                     limits.NewUpperBoundLimiter(memory),
		maxCompressedBinary:        limits.NewUpperBoundLimiter(compressed),
		maxDecompressedBinary:      limits.NewUpperBoundLimiter(decompressed),
		maxResponseSize:            limits.NewUpperBoundLimiter(response),
		pendingCalls:               limits.WorkflowResourcePoolLimiter(pendingCalls),
		enableUserMetrics:          limits.NewGateLimiter(userMetrics),
		maxUserMetricPayload:       limits.NewUpperBoundLimiter(metricPayload),
		maxUserMetricNameLength:    limits.NewUpperBoundLimiter(metricName),
		maxUserMetricLabels:        limits.NewUpperBoundLimiter(metricLabels),
		maxUserMetricLabelValueLen: limits.NewUpperBoundLimiter(metricLabelValue),
		maxSubscriptions:           limits.NewUpperBoundLimiter(subscriptions),
		maxLogLenBytes:             uint32(logLine),
	}
}

func resolveWASMSetting[T any](ctx context.Context, lggr logger.Logger, snapshot *limiterSettingsSnapshot, setting settings.Setting[T]) T {
	var getter settings.Getter
	if snapshot != nil {
		getter = snapshot.getter
	}
	value, err := setting.GetOrDefault(ctx, getter)
	if err != nil {
		// GetOrDefault returns the default alongside the error. Keep settings
		// failures non-fatal rather than passing the error to the WASM host.
		snapshot.logFallback(lggr, setting.Key, err)
	}
	return value
}

func validateMaxLogLenBytes(limit config.Size) error {
	// The WASM host receives the log length as an int32 before comparing it to
	// MaxLogLenBytes, so values outside this range cannot be enforced correctly.
	if limit < 1 || limit > config.Size(math.MaxInt32) {
		return fmt.Errorf("log line limit must be between 1 byte and %d bytes: %s", math.MaxInt32, limit)
	}
	return nil
}

func (l *wasmModuleLimiters) apply(cfg *host.ModuleConfig) {
	cfg.MemoryLimiter = l.memory
	cfg.MaxCompressedBinaryLimiter = l.maxCompressedBinary
	cfg.MaxDecompressedBinaryLimiter = l.maxDecompressedBinary
	cfg.MaxResponseSizeLimiter = l.maxResponseSize
	cfg.PendingCallsLimiter = l.pendingCalls
	cfg.EnableUserMetricsLimiter = l.enableUserMetrics
	cfg.MaxUserMetricPayloadLimiter = l.maxUserMetricPayload
	cfg.MaxUserMetricNameLengthLimiter = l.maxUserMetricNameLength
	cfg.MaxUserMetricLabelsPerMetricLimiter = l.maxUserMetricLabels
	cfg.MaxUserMetricLabelValueLengthLimiter = l.maxUserMetricLabelValueLen
	cfg.MaxSubscriptionsLimiter = l.maxSubscriptions
	cfg.MaxLogLenBytes = l.maxLogLenBytes
}

func (l *wasmModuleLimiters) Close() error {
	return services.CloseAll(l.memory, l.maxCompressedBinary, l.maxDecompressedBinary,
		l.maxResponseSize, l.pendingCalls, l.enableUserMetrics, l.maxUserMetricPayload,
		l.maxUserMetricNameLength, l.maxUserMetricLabels, l.maxUserMetricLabelValueLen, l.maxSubscriptions)
}
