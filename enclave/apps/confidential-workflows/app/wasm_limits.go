package app

import (
	"cmp"
	"math"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// The enclave's own WASM limits, which are the WASM host's built-in defaults.
const (
	enclaveResponseSizeBytes      = uint64(5 * 1024 * 1024)
	enclaveLogLenBytes            = uint64(1024 * 1024)
	enclaveLogCount               = uint32(10_000)
	enclaveCapabilityConcurrency  = uint32(30)
	enclaveUserMetricPayloadBytes = uint64(4096)
	enclaveUserMetricNameLength   = uint32(128)
	enclaveUserMetricLabels       = uint32(20)
	enclaveUserMetricLabelValue   = uint32(256)
)

// applyWASMLimits sets the WASM host limits for one execution from the CRE
// limits the workflow DON sent, taking the more lenient of each sent value and
// the enclave's own. CRE defaults are stricter than the enclave's, so in
// practice only an override above the enclave's value takes effect; moving
// towards CRE's values later only needs this policy to change.
//
// Some sent limits are not applied. WASMMemoryLimit is not, because memory stays
// at the per-execution budget the enclave admits executions against
// (memlimit.PerExecMB). ExecutionTimeout is not, because the injected
// executionTimeout is both the enclave's value and its ceiling.
// ExecutionResponseLimitEnforced is not, because not enforcing is the more
// lenient choice.
//
// The returned func releases the limiters it created and must run after the
// module is closed.
func applyWASMLimits(modCfg *host.ModuleConfig, l *confworkflowtypes.WASMLimits, execReq *sdkpb.ExecuteRequest) func() {
	modCfg.MaxResponseSizeBytes = enclaveResponseSizeBytes
	if l != nil {
		modCfg.MaxResponseSizeBytes = lenient(enclaveResponseSizeBytes, execReq.GetMaxResponseSize())
	}
	// The host compares the log length as an int32.
	modCfg.MaxLogLenBytes = uint32(min(lenient(enclaveLogLenBytes, l.GetLogLineLimitBytes()), math.MaxInt32))
	modCfg.MaxLogCountDONMode = lenient(enclaveLogCount, l.GetLogEventLimit())
	modCfg.MaxLogCountNodeMode = modCfg.MaxLogCountDONMode
	modCfg.MaxUserMetricPayloadBytes = uint32(min(lenient(enclaveUserMetricPayloadBytes, l.GetUserMetricPayloadLimitBytes()), math.MaxUint32))
	modCfg.MaxUserMetricNameLength = lenient(enclaveUserMetricNameLength, l.GetUserMetricNameLengthLimit())
	modCfg.MaxUserMetricLabelsPerMetric = lenient(enclaveUserMetricLabels, l.GetUserMetricLabelsPerMetric())
	modCfg.MaxUserMetricLabelValueLength = lenient(enclaveUserMetricLabelValue, l.GetUserMetricLabelValueLength())

	userMetrics := limits.NewGateLimiter(l.GetUserMetricEnabled())
	pendingCalls := limits.WorkflowResourcePoolLimiter(int(lenient(enclaveCapabilityConcurrency, l.GetCapabilityConcurrencyLimit())))
	modCfg.EnableUserMetricsLimiter = userMetrics
	modCfg.PendingCallsLimiter = pendingCalls
	return func() {
		_ = userMetrics.Close()
		_ = pendingCalls.Close()
	}
}

// lenient returns the more permissive of the enclave's limit and the sent one.
// An unsent value reads as zero, which keeps the enclave's.
func lenient[T cmp.Ordered](ours, sent T) T {
	return max(ours, sent)
}
