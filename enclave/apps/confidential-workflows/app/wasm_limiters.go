package app

import (
	"context"
	"fmt"
	"math"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
)

func resolveWASMLimits(ctx context.Context, lggr logger.Logger, snapshot *limiterSettingsSnapshot) wasmlimits.Config {
	cfg := cresettings.Default.PerWorkflow
	memory := resolveSetting(ctx, lggr, snapshot, cfg.WASMMemoryLimit)
	if memory < config.MByte {
		snapshot.logFallback(lggr, cfg.WASMMemoryLimit.Key, fmt.Errorf("WASM memory limit must be at least 1 MB: %s", memory))
		memory = cfg.WASMMemoryLimit.DefaultValue
	}
	logLine := resolveSetting(ctx, lggr, snapshot, cfg.LogLineLimit)
	if err := validateMaxLogLenBytes(logLine); err != nil {
		snapshot.logFallback(lggr, cfg.LogLineLimit.Key, err)
		logLine = cfg.LogLineLimit.DefaultValue
	}
	compressed := resolveSetting(ctx, lggr, snapshot, cfg.WASMCompressedBinarySizeLimit)
	decompressed := resolveSetting(ctx, lggr, snapshot, cfg.WASMBinarySizeLimit)
	response := resolveSetting(ctx, lggr, snapshot, cfg.ExecutionResponseLimit)
	pendingCalls := resolveSetting(ctx, lggr, snapshot, cfg.CapabilityConcurrencyLimit)
	userMetrics := resolveSetting(ctx, lggr, snapshot, cfg.UserMetricEnabled)
	metricPayload := resolveSetting(ctx, lggr, snapshot, cfg.UserMetricPayloadLimit)
	metricName := resolveSetting(ctx, lggr, snapshot, cfg.UserMetricNameLengthLimit)
	metricLabels := resolveSetting(ctx, lggr, snapshot, cfg.UserMetricLabelsPerMetric)
	metricLabelValue := resolveSetting(ctx, lggr, snapshot, cfg.UserMetricLabelValueLength)
	subscriptions := resolveSetting(ctx, lggr, snapshot, cresettings.Default.WASMPollOneoffSubscriptionLimit)

	if lggr != nil {
		lggr.Debugw("Applied CRE WASM limits",
			cfg.WASMMemoryLimit.Key, memory,
			cfg.WASMCompressedBinarySizeLimit.Key, compressed,
			cfg.WASMBinarySizeLimit.Key, decompressed,
			cfg.ExecutionResponseLimit.Key, response,
			cfg.CapabilityConcurrencyLimit.Key, pendingCalls,
			cfg.LogLineLimit.Key, logLine,
			cfg.UserMetricEnabled.Key, userMetrics,
			cfg.UserMetricPayloadLimit.Key, metricPayload,
			cfg.UserMetricNameLengthLimit.Key, metricName,
			cfg.UserMetricLabelsPerMetric.Key, metricLabels,
			cfg.UserMetricLabelValueLength.Key, metricLabelValue,
			cresettings.Default.WASMPollOneoffSubscriptionLimit.Key, subscriptions)
	}

	return wasmlimits.Config{
		Memory: memory, MaxCompressedBinary: compressed, MaxDecompressedBinary: decompressed,
		MaxResponseSize: response, PendingCalls: pendingCalls, EnableUserMetrics: userMetrics,
		MaxUserMetricPayload: metricPayload, MaxUserMetricNameLength: metricName,
		MaxUserMetricLabels: metricLabels, MaxUserMetricLabelValueLen: metricLabelValue,
		MaxSubscriptions: subscriptions, MaxLogLenBytes: uint32(logLine),
	}
}

func validateMaxLogLenBytes(limit config.Size) error {
	// The WASM host receives the log length as an int32 before comparing it to
	// MaxLogLenBytes, so values outside this range cannot be enforced correctly.
	if limit < 1 || limit > config.Size(math.MaxInt32) {
		return fmt.Errorf("log line limit must be between 1 byte and %d bytes: %s", math.MaxInt32, limit)
	}
	return nil
}
