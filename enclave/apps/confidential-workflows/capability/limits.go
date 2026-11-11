package capability

import (
	"context"
	"fmt"
	"math"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func executionLimitsActive(ctx context.Context, g settings.Getter, s settings.Setting[settings.Range[config.Timestamp]], ts time.Time, lggr logger.SugaredLogger) bool {
	if g == nil {
		return false
	}
	// Requires explicit scoped activation: an env default must not enable limits
	// before the JD snapshot containing customer overrides arrives.
	raw, err := g.GetScoped(ctx, s.Scope, s.Key)
	if err != nil {
		lggr.Warnw("Not sending CRE limits: activation setting unavailable", "key", s.Key, "err", err)
		return false
	}
	if raw == "" {
		return false
	}
	window, err := s.Parse(raw)
	if err != nil {
		lggr.Warnw("Not sending CRE limits: invalid activation setting", "key", s.Key, "err", err)
		return false
	}
	if ts.IsZero() {
		lggr.Warnw("Not sending CRE limits: execution timestamp unavailable", "key", s.Key)
		return false
	}
	return window.Contains(config.Timestamp(ts.Unix()))
}

// resolveExecutionLimits reads the CRE limits for the execution's org, owner
// and workflow (carried by ctx) from the node's settings, the source the
// workflow engine uses for non-confidential executions, so a customer's
// override applies the same way in both. It sends every limit it can resolve
// and decides nothing: how each one applies is the enclave's policy.
//
// Nothing here falls back to cresettings defaults on a failure: an invalid or
// negative value leaves that one limit unset, so a settings problem cannot turn
// into enforcement of a default over an override (INCIDENT-2784). A value that
// is merely absent resolves to the default, exactly as in the engine.
func resolveExecutionLimits(ctx context.Context, g settings.Getter, lggr logger.SugaredLogger) *confworkflowtypes.ExecutionLimits {
	if g == nil {
		return nil
	}
	r := limitResolver{ctx: ctx, g: g, lggr: lggr}
	h := cresettings.Default.PerWorkflow.HTTPAction
	w := cresettings.Default.PerWorkflow
	return &confworkflowtypes.ExecutionLimits{
		HttpAction: &confworkflowtypes.HTTPActionLimits{
			CallLimit:              uint32Limit(r, &h.CallLimit),
			RequestSizeLimitBytes:  uint64Limit(r, &h.RequestSizeLimit),
			ResponseSizeLimitBytes: uint64Limit(r, &h.ResponseSizeLimit),
			ConnectionTimeout:      durationLimit(r, &h.ConnectionTimeout),
		},
		Wasm: &confworkflowtypes.WASMLimits{
			MemoryLimitBytes:            uint64Limit(r, &w.WASMMemoryLimit),
			ExecutionTimeout:            durationLimit(r, &w.ExecutionTimeout),
			ResponseLimitEnforced:       flag(r, &w.ExecutionResponseLimitEnforced),
			CapabilityConcurrencyLimit:  uint32Limit(r, &w.CapabilityConcurrencyLimit),
			LogLineLimitBytes:           uint64Limit(r, &w.LogLineLimit),
			LogEventLimit:               uint32Limit(r, &w.LogEventLimit),
			UserMetricEnabled:           flag(r, &w.UserMetricEnabled),
			UserMetricPayloadLimitBytes: uint64Limit(r, &w.UserMetricPayloadLimit),
			UserMetricNameLengthLimit:   uint32Limit(r, &w.UserMetricNameLengthLimit),
			UserMetricLabelsPerMetric:   uint32Limit(r, &w.UserMetricLabelsPerMetric),
			UserMetricLabelValueLength:  uint32Limit(r, &w.UserMetricLabelValueLength),
		},
	}
}

type limitResolver struct {
	ctx  context.Context
	g    settings.Getter
	lggr logger.SugaredLogger
}

// resolveLimit reads one numeric limit, reporting false for a lookup error or a
// negative value so the caller leaves that limit unset instead of sending the
// default or a wrapped unsigned value.
func resolveLimit[T ~int | ~int64](r limitResolver, s *settings.Setting[T]) (T, bool) {
	v, err := s.GetOrDefault(r.ctx, r.g)
	if err == nil && v < 0 {
		err = fmt.Errorf("negative value %v", v)
	}
	if err != nil {
		r.lggr.Warnw("Not sending a CRE limit to the enclave: invalid setting", "key", s.Key, "err", err)
		return 0, false
	}
	return v, true
}

func uint32Limit[T ~int | ~int64](r limitResolver, s *settings.Setting[T]) *uint32 {
	v, ok := resolveLimit(r, s)
	if !ok {
		return nil
	}
	return proto.Uint32(uint32(min(int64(v), math.MaxUint32))) //nolint:gosec // bounded above
}

func uint64Limit[T ~int | ~int64](r limitResolver, s *settings.Setting[T]) *uint64 {
	v, ok := resolveLimit(r, s)
	if !ok {
		return nil
	}
	return proto.Uint64(uint64(v)) //nolint:gosec // non-negative
}

func durationLimit(r limitResolver, s *settings.Setting[time.Duration]) *durationpb.Duration {
	v, ok := resolveLimit(r, s)
	if !ok {
		return nil
	}
	return durationpb.New(v)
}

func flag(r limitResolver, s *settings.Setting[bool]) *bool {
	v, err := s.GetOrDefault(r.ctx, r.g)
	if err != nil {
		r.lggr.Warnw("Not sending a CRE limit to the enclave: invalid setting", "key", s.Key, "err", err)
		return nil
	}
	return proto.Bool(v)
}
