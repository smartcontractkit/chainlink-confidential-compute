package app

import (
	"errors"
	"fmt"
	"io"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
)

const (
	// Matches CRE's 100mb default: https://github.com/smartcontractkit/chainlink-common/blob/a8f860eb5f61b1bdae0f11ef03b996285c8125f5/pkg/settings/cresettings/defaults.toml#L116
	defaultWASMMemoryLimit             = config.Size(100) * config.MByte
	defaultWASMCompressedBinaryLimit   = config.Size(20 * 1024 * 1024)
	defaultWASMDecompressedBinaryLimit = config.Size(100 * 1024 * 1024)
	defaultWASMResponseLimit           = config.Size(5 * 1024 * 1024)
	defaultUserMetricPayloadLimit      = config.Size(4096)
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
	closers                    []io.Closer
}

type settingParser func(string) error

func parserFor[T any](setting settings.Setting[T]) settingParser {
	return func(value string) error {
		_, err := setting.Parse(value)
		return err
	}
}

func memoryLimitParser(setting settings.Setting[config.Size]) settingParser {
	return func(value string) error {
		limit, err := setting.Parse(value)
		if err != nil {
			return err
		}
		if limit < config.MByte {
			return fmt.Errorf("WASM memory limit must be at least 1 MB")
		}
		return nil
	}
}

func wasmLimiterSettingParsers() map[string]settingParser {
	cfg := cresettings.Default.PerWorkflow
	subscriptions := cresettings.Default.WASMPollOneoffSubscriptionLimit
	return map[string]settingParser{
		cfg.WASMMemoryLimit.Key:               memoryLimitParser(cfg.WASMMemoryLimit),
		cfg.WASMCompressedBinarySizeLimit.Key: parserFor(cfg.WASMCompressedBinarySizeLimit),
		cfg.WASMBinarySizeLimit.Key:           parserFor(cfg.WASMBinarySizeLimit),
		cfg.ExecutionResponseLimit.Key:        parserFor(cfg.ExecutionResponseLimit),
		cfg.CapabilityConcurrencyLimit.Key:    parserFor(cfg.CapabilityConcurrencyLimit),
		cfg.UserMetricEnabled.Key:             parserFor(cfg.UserMetricEnabled),
		cfg.UserMetricPayloadLimit.Key:        parserFor(cfg.UserMetricPayloadLimit),
		cfg.UserMetricNameLengthLimit.Key:     parserFor(cfg.UserMetricNameLengthLimit),
		cfg.UserMetricLabelsPerMetric.Key:     parserFor(cfg.UserMetricLabelsPerMetric),
		cfg.UserMetricLabelValueLength.Key:    parserFor(cfg.UserMetricLabelValueLength),
		subscriptions.Key:                     parserFor(subscriptions),
	}
}

func newWASMModuleLimiters(factory limits.Factory) (_ *wasmModuleLimiters, err error) {
	l := &wasmModuleLimiters{}
	defer func() {
		if err != nil {
			err = errors.Join(err, l.Close())
		}
	}()

	cfg := cresettings.Default.PerWorkflow
	// Retain the named settings' keys and scopes so injected CRE settings can
	// override them. Memory matches CRE's current default but is pinned locally
	// via defaultWASMMemoryLimit, so an upstream change cannot silently move
	// this attested limit; it intentionally supersedes the host's 128 MB
	// MinMemoryMBs floor. The remaining DefaultValue overrides preserve the
	// enclave's previous WASM host fallbacks.
	cfg.WASMMemoryLimit.DefaultValue = defaultWASMMemoryLimit
	cfg.WASMCompressedBinarySizeLimit.DefaultValue = defaultWASMCompressedBinaryLimit
	cfg.WASMBinarySizeLimit.DefaultValue = defaultWASMDecompressedBinaryLimit
	cfg.ExecutionResponseLimit.DefaultValue = defaultWASMResponseLimit
	cfg.UserMetricPayloadLimit.DefaultValue = defaultUserMetricPayloadLimit

	l.memory, err = limits.MakeUpperBoundLimiter(factory, cfg.WASMMemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("building WASM memory limiter: %w", err)
	}
	l.closers = append(l.closers, l.memory)

	l.maxCompressedBinary, err = limits.MakeUpperBoundLimiter(factory, cfg.WASMCompressedBinarySizeLimit)
	if err != nil {
		return nil, fmt.Errorf("building compressed WASM binary limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxCompressedBinary)

	l.maxDecompressedBinary, err = limits.MakeUpperBoundLimiter(factory, cfg.WASMBinarySizeLimit)
	if err != nil {
		return nil, fmt.Errorf("building decompressed WASM binary limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxDecompressedBinary)

	l.maxResponseSize, err = limits.MakeUpperBoundLimiter(factory, cfg.ExecutionResponseLimit)
	if err != nil {
		return nil, fmt.Errorf("building WASM response limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxResponseSize)

	l.pendingCalls, err = limits.MakeResourcePoolLimiter(factory, cfg.CapabilityConcurrencyLimit)
	if err != nil {
		return nil, fmt.Errorf("building pending calls limiter: %w", err)
	}
	l.closers = append(l.closers, l.pendingCalls)

	l.enableUserMetrics, err = limits.MakeGateLimiter(factory, cfg.UserMetricEnabled)
	if err != nil {
		return nil, fmt.Errorf("building user metrics gate limiter: %w", err)
	}
	l.closers = append(l.closers, l.enableUserMetrics)

	l.maxUserMetricPayload, err = limits.MakeUpperBoundLimiter(factory, cfg.UserMetricPayloadLimit)
	if err != nil {
		return nil, fmt.Errorf("building user metric payload limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxUserMetricPayload)

	l.maxUserMetricNameLength, err = limits.MakeUpperBoundLimiter(factory, cfg.UserMetricNameLengthLimit)
	if err != nil {
		return nil, fmt.Errorf("building user metric name length limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxUserMetricNameLength)

	l.maxUserMetricLabels, err = limits.MakeUpperBoundLimiter(factory, cfg.UserMetricLabelsPerMetric)
	if err != nil {
		return nil, fmt.Errorf("building user metric labels limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxUserMetricLabels)

	l.maxUserMetricLabelValueLen, err = limits.MakeUpperBoundLimiter(factory, cfg.UserMetricLabelValueLength)
	if err != nil {
		return nil, fmt.Errorf("building user metric label value length limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxUserMetricLabelValueLen)

	l.maxSubscriptions, err = limits.MakeUpperBoundLimiter(factory, cresettings.Default.WASMPollOneoffSubscriptionLimit)
	if err != nil {
		return nil, fmt.Errorf("building WASI poll_oneoff subscription limiter: %w", err)
	}
	l.closers = append(l.closers, l.maxSubscriptions)

	return l, nil
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
}

func (l *wasmModuleLimiters) Close() error {
	return services.CloseAll(l.closers...)
}
