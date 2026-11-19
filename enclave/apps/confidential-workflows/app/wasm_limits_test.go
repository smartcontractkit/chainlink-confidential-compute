package app

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
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

func readBound[T limits.Number](t *testing.T, l limits.BoundLimiter[T]) T {
	t.Helper()
	require.NotNil(t, l)
	v, err := l.Limit(t.Context())
	require.NoError(t, err)
	return v
}

func TestApplyWASMLimits_NothingSentKeepsEnclaveDefaults(t *testing.T) {
	for _, req := range []*sdkpb.ExecuteRequest{nil, {MaxResponseSize: 8 * 1024 * 1024}} {
		cfg := &host.ModuleConfig{}
		applyWASMLimits(cfg, nil, req)()
		assert.Equal(t, &host.ModuleConfig{}, cfg)
	}
	cfg := &host.ModuleConfig{}
	applyWASMLimits(cfg, &confworkflowtypes.WASMLimits{}, nil)()
	assert.Equal(t, &host.ModuleConfig{}, cfg)
}

func TestApplyWASMLimits_ResolvedValuesApply(t *testing.T) {
	operatorTimeout := 150 * time.Second
	cfg := &host.ModuleConfig{Timeout: &operatorTimeout}
	l := &confworkflowtypes.WASMLimits{
		MemoryLimitBytes: proto.Uint64(100_000_000), ExecutionTimeout: durationpb.New(time.Minute),
		ResponseLimitEnforced: proto.Bool(true), CapabilityConcurrencyLimit: proto.Uint32(7),
		LogLineLimitBytes: proto.Uint64(1000), LogEventLimit: proto.Uint32(1000),
		UserMetricEnabled: proto.Bool(true), UserMetricPayloadLimitBytes: proto.Uint64(4000),
		UserMetricNameLengthLimit: proto.Uint32(32), UserMetricLabelsPerMetric: proto.Uint32(4),
		UserMetricLabelValueLength: proto.Uint32(64),
	}
	t.Cleanup(applyWASMLimits(cfg, l, &sdkpb.ExecuteRequest{MaxResponseSize: 100_000}))
	assert.Equal(t, config.Size(100_000_000), readBound(t, cfg.MemoryLimiter))
	assert.Equal(t, time.Minute, *cfg.Timeout)
	assert.Equal(t, config.Size(100_000), readBound(t, cfg.MaxResponseSizeLimiter))
	enforced, err := cfg.EnforceResponseSizeLimiter.IsOpen(t.Context())
	require.NoError(t, err)
	assert.True(t, enforced)
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Workflow: "workflow"})
	calls, err := cfg.PendingCallsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 7, calls)
	assert.Equal(t, uint32(1000), cfg.MaxLogLenBytes)
	assert.Equal(t, uint32(1000), cfg.MaxLogCountDONMode)
	assert.Equal(t, cfg.MaxLogCountDONMode, cfg.MaxLogCountNodeMode)
	assert.Equal(t, config.Size(4000), readBound(t, cfg.MaxUserMetricPayloadLimiter))
	assert.Equal(t, 32, readBound(t, cfg.MaxUserMetricNameLengthLimiter))
	assert.Equal(t, 4, readBound(t, cfg.MaxUserMetricLabelsPerMetricLimiter))
	assert.Equal(t, 64, readBound(t, cfg.MaxUserMetricLabelValueLengthLimiter))
	assert.Nil(t, cfg.EnableUserMetricsLimiter, "host gate stays closed until bounded forwarding exists")
}

func TestApplyWASMLimits_Ceilings(t *testing.T) {
	operatorTimeout := 150 * time.Second
	cfg := &host.ModuleConfig{Timeout: &operatorTimeout}
	t.Cleanup(applyWASMLimits(cfg, &confworkflowtypes.WASMLimits{
		MemoryLimitBytes: proto.Uint64(math.MaxUint64), ExecutionTimeout: durationpb.New(time.Hour),
		LogLineLimitBytes:           proto.Uint64(math.MaxUint64),
		CapabilityConcurrencyLimit:  proto.Uint32(31),
		UserMetricPayloadLimitBytes: proto.Uint64(math.MaxUint64),
	}, &sdkpb.ExecuteRequest{MaxResponseSize: math.MaxUint64}))
	assert.Equal(t, config.Size(128_000_000), readBound(t, cfg.MemoryLimiter))
	assert.Equal(t, operatorTimeout, *cfg.Timeout)
	assert.Equal(t, config.Size(enclaveResponseSizeBytes), readBound(t, cfg.MaxResponseSizeLimiter))
	assert.Equal(t, uint32(math.MaxInt32), cfg.MaxLogLenBytes)
	assert.Equal(t, config.Size(math.MaxInt64), readBound(t, cfg.MaxUserMetricPayloadLimiter))
	calls, err := cfg.PendingCallsLimiter.Limit(contexts.WithCRE(t.Context(), contexts.CRE{Workflow: "workflow"}))
	require.NoError(t, err)
	assert.Equal(t, 31, calls, "a valid override is not replaced with a host default")
}

func TestApplyWASMLimits_ExplicitZero(t *testing.T) {
	cfg := &host.ModuleConfig{}
	t.Cleanup(applyWASMLimits(cfg, &confworkflowtypes.WASMLimits{
		MemoryLimitBytes: proto.Uint64(0), ExecutionTimeout: durationpb.New(0),
		ResponseLimitEnforced: proto.Bool(false), CapabilityConcurrencyLimit: proto.Uint32(0),
		LogLineLimitBytes: proto.Uint64(0), LogEventLimit: proto.Uint32(0),
		UserMetricPayloadLimitBytes: proto.Uint64(0), UserMetricNameLengthLimit: proto.Uint32(0),
		UserMetricLabelsPerMetric: proto.Uint32(0), UserMetricLabelValueLength: proto.Uint32(0),
	}, &sdkpb.ExecuteRequest{}))
	assert.Zero(t, readBound(t, cfg.MemoryLimiter))
	assert.Zero(t, *cfg.Timeout)
	assert.Zero(t, readBound(t, cfg.MaxResponseSizeLimiter))
	enforced, err := cfg.EnforceResponseSizeLimiter.IsOpen(t.Context())
	require.NoError(t, err)
	assert.False(t, enforced)
	calls, err := cfg.PendingCallsLimiter.Limit(contexts.WithCRE(t.Context(), contexts.CRE{Workflow: "workflow"}))
	require.NoError(t, err)
	assert.Zero(t, calls)
	assert.Zero(t, readBound(t, cfg.MaxUserMetricPayloadLimiter))
	assert.Zero(t, readBound(t, cfg.MaxUserMetricNameLengthLimiter))
	assert.Zero(t, readBound(t, cfg.MaxUserMetricLabelsPerMetricLimiter))
	assert.Zero(t, readBound(t, cfg.MaxUserMetricLabelValueLengthLimiter))
}

func TestApplyWASMLimits_InvalidTimeoutIgnored(t *testing.T) {
	for _, d := range []*durationpb.Duration{durationpb.New(-time.Second), {Seconds: math.MaxInt64}} {
		timeout := time.Minute
		cfg := &host.ModuleConfig{Timeout: &timeout}
		applyWASMLimits(cfg, &confworkflowtypes.WASMLimits{ExecutionTimeout: d}, nil)()
		assert.Equal(t, time.Minute, *cfg.Timeout)
	}
}

func TestExecuteWasm_WASMLimits(t *testing.T) {
	binary := buildTestWasm(t, "hello")
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		limits    *confworkflowtypes.WASMLimits
		size      uint64
		wantError bool
	}{
		{name: "legacy", size: 8 * 1024 * 1024},
		{name: "strict", limits: &confworkflowtypes.WASMLimits{MemoryLimitBytes: proto.Uint64(100_000_000)}, size: 100_000},
		{name: "response rejection", limits: &confworkflowtypes.WASMLimits{ResponseLimitEnforced: proto.Bool(true)}, size: 1, wantError: true},
		{name: "response rejection disabled", limits: &confworkflowtypes.WASMLimits{ResponseLimitEnforced: proto.Bool(false)}, size: 1},
		{name: "zero memory", limits: &confworkflowtypes.WASMLimits{MemoryLimitBytes: proto.Uint64(0)}, size: 100_000, wantError: true},
		{name: "zero timeout", limits: &confworkflowtypes.WASMLimits{ExecutionTimeout: durationpb.New(0)}, size: 100_000, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &sdkpb.ExecuteRequest{MaxResponseSize: tc.size, Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: payload}}}
			ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
			result, err := executeWasm(ctx, logger.Test(t), &recordingEmitter{}, semaphore.NewWeighted(1), binary, req, false, &enclaveExecutionHelper{}, 0, tc.limits)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
			if tc.limits == nil {
				assert.Equal(t, enclaveResponseSizeBytes, req.MaxResponseSize)
			}
		})
	}
}

func TestExecuteWasm_HTTPResponseBuffer(t *testing.T) {
	binary := buildTestWasm(t, "http-call")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100_001)))
	}))
	t.Cleanup(server.Close)
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	for _, size := range []uint64{100_000, 1_000_000} {
		req := &sdkpb.ExecuteRequest{Config: []byte(server.URL), MaxResponseSize: size,
			Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: payload}}}
		ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
		helper := &enclaveExecutionHelper{httpFetcher: permissiveFetcher(), httpLimits: newHTTPActionLimits(&confworkflowtypes.ExecutionLimits{
			HttpAction: &confworkflowtypes.HTTPActionLimits{ResponseSizeLimitBytes: proto.Uint64(300_000)},
		})}
		result, err := executeWasm(ctx, logger.Test(t), &recordingEmitter{}, semaphore.NewWeighted(1), binary, req, false, helper, 0,
			&confworkflowtypes.WASMLimits{ResponseLimitEnforced: proto.Bool(false)})
		require.NoError(t, err)
		if size == 100_000 {
			require.NotEmpty(t, result.GetError(), "an HTTP override alone cannot enlarge the guest response buffer")
		} else {
			require.Empty(t, result.GetError(), "the execution response override must reach the guest buffer")
		}
	}
}

func TestUserLogLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits *confworkflowtypes.WASMLimits
		want   int
	}{
		{name: "legacy", want: 2},
		{name: "zero count", limits: &confworkflowtypes.WASMLimits{LogEventLimit: proto.Uint32(0)}},
		{name: "zero length", limits: &confworkflowtypes.WASMLimits{LogLineLimitBytes: proto.Uint64(0)}},
		{name: "one log", limits: &confworkflowtypes.WASMLimits{LogEventLimit: proto.Uint32(1)}, want: 1},
		{name: "too long", limits: &confworkflowtypes.WASMLimits{LogLineLimitBytes: proto.Uint64(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter := &recordingEmitter{}
			h := &enclaveExecutionHelper{emitter: emitter, wasmLimits: tc.limits}
			require.NoError(t, h.EmitUserLog("hello"))
			require.NoError(t, h.EmitUserLog("again"))
			assert.Equal(t, tc.want, emitter.countOf("user_log"))
		})
	}
}
