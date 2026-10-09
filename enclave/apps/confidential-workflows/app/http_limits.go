package app

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
)

type httpActionLimits struct {
	callLimit int
	fetch     httpfetch.Limits
}

func newHTTPActionLimits(ctx context.Context, lggr logger.Logger, snapshot *limiterSettingsSnapshot) httpActionLimits {
	cfg := cresettings.Default.PerWorkflow.HTTPAction
	l := httpActionLimits{
		callLimit: resolveHTTPSetting(ctx, lggr, snapshot, cfg.CallLimit),
		fetch: httpfetch.Limits{
			ConnectionTimeout: resolveHTTPSetting(ctx, lggr, snapshot, cfg.ConnectionTimeout),
			RequestSizeLimit:  resolveHTTPSetting(ctx, lggr, snapshot, cfg.RequestSizeLimit),
			ResponseSizeLimit: resolveHTTPSetting(ctx, lggr, snapshot, cfg.ResponseSizeLimit),
		},
	}
	if lggr != nil {
		lggr.Debugw("Applied CRE HTTP action limits",
			cfg.CallLimit.Key, l.callLimit,
			cfg.ConnectionTimeout.Key, l.fetch.ConnectionTimeout,
			cfg.RequestSizeLimit.Key, l.fetch.RequestSizeLimit,
			cfg.ResponseSizeLimit.Key, l.fetch.ResponseSizeLimit)
	}
	return l
}

func resolveHTTPSetting[T limits.Number](ctx context.Context, lggr logger.Logger, snapshot *limiterSettingsSnapshot, setting settings.Setting[T]) T {
	value := resolveSetting(ctx, lggr, snapshot, setting)
	if value < 0 {
		snapshot.logFallback(lggr, setting.Key, fmt.Errorf("HTTP action limit cannot be negative: %v", value))
		return setting.DefaultValue
	}
	return value
}
