package app

import (
	"context"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// wasmLimitsResult applies limits to a fresh module config and returns the
// resulting values, including the limits held by the configured limiters.
type wasmLimitsResult struct {
	responseSize, logLen, logCountDON, logCountNode                  uint64
	metricPayload, metricName, metricLabels, metricLabelValue, calls uint64
	userMetrics                                                      bool
}

func applyForTest(t *testing.T, l *confworkflowtypes.WASMLimits, execReq *sdkpb.ExecuteRequest) wasmLimitsResult {
	t.Helper()
	cfg := &host.ModuleConfig{}
	cleanup := applyWASMLimits(cfg, l, execReq)
	t.Cleanup(cleanup)
	ctx := contexts.WithCRE(context.Background(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	calls, err := cfg.PendingCallsLimiter.Limit(ctx)
	require.NoError(t, err)
	userMetrics, err := cfg.EnableUserMetricsLimiter.IsOpen(ctx)
	require.NoError(t, err)
	return wasmLimitsResult{
		responseSize:     cfg.MaxResponseSizeBytes,
		logLen:           uint64(cfg.MaxLogLenBytes),
		logCountDON:      uint64(cfg.MaxLogCountDONMode),
		logCountNode:     uint64(cfg.MaxLogCountNodeMode),
		metricPayload:    uint64(cfg.MaxUserMetricPayloadBytes),
		metricName:       uint64(cfg.MaxUserMetricNameLength),
		metricLabels:     uint64(cfg.MaxUserMetricLabelsPerMetric),
		metricLabelValue: uint64(cfg.MaxUserMetricLabelValueLength),
		calls:            uint64(calls),
		userMetrics:      userMetrics,
	}
}

// enclaveDefaults are the WASM host's built-in defaults, which the enclave
// used before it received any CRE limits.
var enclaveDefaults = wasmLimitsResult{
	responseSize: 5 * 1024 * 1024, logLen: 1024 * 1024, logCountDON: 10_000, logCountNode: 10_000,
	metricPayload: 4096, metricName: 128, metricLabels: 20, metricLabelValue: 256, calls: 30,
}

func TestApplyWASMLimits_NothingSentKeepsEnclaveDefaults(t *testing.T) {
	assert.Equal(t, enclaveDefaults, applyForTest(t, nil, nil))
	assert.Equal(t, enclaveDefaults, applyForTest(t, nil, &sdkpb.ExecuteRequest{MaxResponseSize: 8 * 1024 * 1024}))
	assert.Equal(t, enclaveDefaults, applyForTest(t, &confworkflowtypes.WASMLimits{}, &sdkpb.ExecuteRequest{}))
}

// The CRE defaults are stricter than the enclave's own values, so sending them
// changes nothing.
func TestApplyWASMLimits_CREDefaultsDoNotTighten(t *testing.T) {
	creDefaults := &confworkflowtypes.WASMLimits{
		MemoryLimitBytes:            proto.Uint64(100_000_000),
		ExecutionTimeout:            durationpb.New(5 * time.Minute),
		ResponseLimitEnforced:       proto.Bool(false),
		CapabilityConcurrencyLimit:  proto.Uint32(30),
		LogLineLimitBytes:           proto.Uint64(1000),
		LogEventLimit:               proto.Uint32(1000),
		UserMetricEnabled:           proto.Bool(false),
		UserMetricPayloadLimitBytes: proto.Uint64(4000),
		UserMetricNameLengthLimit:   proto.Uint32(128),
		UserMetricLabelsPerMetric:   proto.Uint32(20),
		UserMetricLabelValueLength:  proto.Uint32(256),
	}
	assert.Equal(t, enclaveDefaults, applyForTest(t, creDefaults, &sdkpb.ExecuteRequest{MaxResponseSize: 100_000}))
}

// An override above the enclave's own value takes effect.
func TestApplyWASMLimits_LooserOverridesApply(t *testing.T) {
	overrides := &confworkflowtypes.WASMLimits{
		CapabilityConcurrencyLimit:  proto.Uint32(31),
		LogLineLimitBytes:           proto.Uint64(2 * 1024 * 1024),
		LogEventLimit:               proto.Uint32(20_000),
		UserMetricEnabled:           proto.Bool(true),
		UserMetricPayloadLimitBytes: proto.Uint64(8192),
		UserMetricNameLengthLimit:   proto.Uint32(256),
		UserMetricLabelsPerMetric:   proto.Uint32(40),
		UserMetricLabelValueLength:  proto.Uint32(512),
	}
	assert.Equal(t, wasmLimitsResult{
		responseSize: 8 * 1024 * 1024, logLen: 2 * 1024 * 1024, logCountDON: 20_000, logCountNode: 20_000,
		metricPayload: 8192, metricName: 256, metricLabels: 40, metricLabelValue: 512, calls: 31,
		userMetrics: true,
	}, applyForTest(t, overrides, &sdkpb.ExecuteRequest{MaxResponseSize: 8 * 1024 * 1024}))
}

func TestApplyWASMLimits_LogLengthStaysInt32(t *testing.T) {
	got := applyForTest(t, &confworkflowtypes.WASMLimits{LogLineLimitBytes: proto.Uint64(1 << 40)}, nil)
	assert.Equal(t, uint64(1<<31-1), got.logLen)
}

// A WASM run with limits sent must still execute normally.
func TestExecuteWasm_WithWASMLimits(t *testing.T) {
	binary := buildTestWasm(t, "hello")
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execReq := &sdkpb.ExecuteRequest{
		MaxResponseSize: 100_000,
		Request:         &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: payload}},
	}
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	limits := &confworkflowtypes.WASMLimits{UserMetricEnabled: proto.Bool(true), CapabilityConcurrencyLimit: proto.Uint32(31)}
	result, err := executeWasm(ctx, logger.Test(t), &recordingEmitter{}, semaphore.NewWeighted(1), binary, execReq, false, &enclaveExecutionHelper{}, 0, limits)
	require.NoError(t, err)
	require.NotNil(t, result)
}
