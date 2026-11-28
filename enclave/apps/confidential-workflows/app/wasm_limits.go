package app

import (
	"io"
	"math"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

const enclaveResponseSizeBytes = uint64(5 * 1024 * 1024)

// applyWASMLimits applies only provided values. Nil preserves host defaults;
// fixed-value limiters preserve explicit zero without resolving settings again.
// Admission memory, response buffering and the operator timeout remain ceilings.
// The returned cleanup must run after the module is closed.
func applyWASMLimits(cfg *host.ModuleConfig, l *confworkflowtypes.WASMLimits, req *sdkpb.ExecuteRequest) func() {
	if l == nil {
		return func() {}
	}
	if l.MemoryLimitBytes != nil {
		cfg.MemoryLimiter = limits.NewUpperBoundLimiter(config.Size(min(l.GetMemoryLimitBytes(), uint64(memlimit.PerExecMB)*uint64(config.MByte))))
	}
	if d := l.ExecutionTimeout; d != nil && d.CheckValid() == nil && d.AsDuration() >= 0 {
		ceiling := 10 * time.Minute // Matches the host default when no operator timeout is injected.
		if cfg.Timeout != nil {
			ceiling = *cfg.Timeout
		}
		timeout := min(d.AsDuration(), ceiling)
		cfg.Timeout = &timeout
	}
	if req != nil {
		cfg.MaxResponseSizeLimiter = limits.NewUpperBoundLimiter(config.Size(min(req.GetMaxResponseSize(), enclaveResponseSizeBytes)))
	}
	if l.ResponseLimitEnforced != nil {
		cfg.EnforceResponseSizeLimiter = limits.NewGateLimiter(l.GetResponseLimitEnforced())
	}
	if l.CapabilityConcurrencyLimit != nil {
		cfg.PendingCallsLimiter = limits.WorkflowResourcePoolLimiter(int(l.GetCapabilityConcurrencyLimit()))
	}
	if l.LogLineLimitBytes != nil {
		cfg.MaxLogLenBytes = uint32(min(l.GetLogLineLimitBytes(), math.MaxInt32))
	}
	if l.LogEventLimit != nil {
		cfg.MaxLogCountDONMode = l.GetLogEventLimit()
		cfg.MaxLogCountNodeMode = l.GetLogEventLimit()
	}
	// User metrics stay disabled until bounded, end-to-end forwarding exists.
	// Opening the host gate today would buffer events that customers never receive.
	if l.UserMetricPayloadLimitBytes != nil {
		cfg.MaxUserMetricPayloadLimiter = limits.NewUpperBoundLimiter(config.Size(min(l.GetUserMetricPayloadLimitBytes(), math.MaxInt64)))
	}
	if l.UserMetricNameLengthLimit != nil {
		cfg.MaxUserMetricNameLengthLimiter = limits.NewUpperBoundLimiter(int(l.GetUserMetricNameLengthLimit()))
	}
	if l.UserMetricLabelsPerMetric != nil {
		cfg.MaxUserMetricLabelsPerMetricLimiter = limits.NewUpperBoundLimiter(int(l.GetUserMetricLabelsPerMetric()))
	}
	if l.UserMetricLabelValueLength != nil {
		cfg.MaxUserMetricLabelValueLengthLimiter = limits.NewUpperBoundLimiter(int(l.GetUserMetricLabelValueLength()))
	}
	return func() {
		for _, c := range []io.Closer{
			cfg.MemoryLimiter, cfg.MaxResponseSizeLimiter, cfg.EnforceResponseSizeLimiter,
			cfg.PendingCallsLimiter, cfg.MaxUserMetricPayloadLimiter,
			cfg.MaxUserMetricNameLengthLimiter, cfg.MaxUserMetricLabelsPerMetricLimiter,
			cfg.MaxUserMetricLabelValueLengthLimiter,
		} {
			if c != nil {
				_ = c.Close()
			}
		}
	}
}
