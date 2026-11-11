package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const limitsWindow = "[2030-01-01 00:00:00 +0000 UTC,2030-01-02 00:00:00 +0000 UTC]"

var limitsTimestamp = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

type gateGetterFunc func(context.Context, settings.Scope, string) (string, error)

func (f gateGetterFunc) GetScoped(ctx context.Context, scope settings.Scope, key string) (string, error) {
	return f(ctx, scope, key)
}

func TestExecutionLimitsActive(t *testing.T) {
	s := cresettings.Default.PerWorkflow.FeatureConfidentialWorkflowExecutionLimitsActivePeriod
	// Even a default overridden through CL_CRE_SETTINGS_DEFAULT cannot activate
	// limits without an explicit value in the scoped settings source.
	s.DefaultValue, _ = s.Parse(limitsWindow)
	metadata := testMetadata()
	configured := jsonGetter(t, `{"global":{"PerWorkflow":{"FeatureConfidentialWorkflowExecutionLimitsActivePeriod":"`+limitsWindow+`"}}}`)
	for _, tt := range []struct {
		name string
		g    settings.Getter
		ts   time.Time
		want bool
	}{
		{name: "nil getter", ts: limitsTimestamp},
		{name: "default only", g: jsonGetter(t, `{}`), ts: limitsTimestamp},
		{name: "unloaded atomic", g: &settings.Atomic{}, ts: limitsTimestamp},
		{name: "invalid window", g: gateGetterFunc(func(context.Context, settings.Scope, string) (string, error) { return "invalid", nil }), ts: limitsTimestamp},
		{name: "read error with usable value", g: gateGetterFunc(func(context.Context, settings.Scope, string) (string, error) {
			return limitsWindow, errors.New("unavailable")
		}), ts: limitsTimestamp},
		{name: "no timestamp", g: configured},
		{name: "zero included in window", g: gateGetterFunc(func(context.Context, settings.Scope, string) (string, error) {
			return "[0001-01-01 00:00:00 +0000 UTC,2100-01-01 00:00:00 +0000 UTC]", nil
		})},
		{name: "before", g: configured, ts: time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC)},
		{name: "start inclusive", g: configured, ts: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "active", g: configured, ts: limitsTimestamp, want: true},
		{name: "end inclusive", g: configured, ts: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), want: true},
		{name: "expired", g: configured, ts: time.Date(2030, 1, 2, 0, 0, 1, 0, time.UTC)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, executionLimitsActive(metadata.ContextWithCRE(t.Context()), tt.g, s, tt.ts, logger.Sugared(logger.Test(t))))
		})
	}
}

func TestExecutionLimitsActive_ScopedWindow(t *testing.T) {
	g := jsonGetter(t, `{
		"global":{"PerWorkflow":{"FeatureConfidentialWorkflowExecutionLimitsActivePeriod":"`+limitsWindow+`"}},
		"org":{"org-1":{"PerWorkflow":{"FeatureConfidentialWorkflowExecutionLimitsActivePeriod":"[2100-01-01 00:00:00 +0000 UTC,2101-01-01 00:00:00 +0000 UTC]"}}},
		"owner":{"`+overrideOwner+`":{"PerWorkflow":{"FeatureConfidentialWorkflowExecutionLimitsActivePeriod":"`+limitsWindow+`"}}},
		"workflow":{"wf-off":{"PerWorkflow":{"FeatureConfidentialWorkflowExecutionLimitsActivePeriod":"[2100-01-01 00:00:00 +0000 UTC,2101-01-01 00:00:00 +0000 UTC]"}}}
	}`)
	s := cresettings.Default.PerWorkflow.FeatureConfidentialWorkflowExecutionLimitsActivePeriod
	for _, tt := range []struct {
		org, owner, workflow string
		want                 bool
	}{
		{"org-2", plainOwner, "wf-1", true},
		{"org-1", plainOwner, "wf-1", false},
		{"org-1", overrideOwner, "wf-1", true},
		{"org-1", overrideOwner, "wf-off", false},
	} {
		assert.Equal(t, tt.want, executionLimitsActive(creCtx(tt.org, tt.owner, tt.workflow), g, s, limitsTimestamp, logger.Sugared(logger.Test(t))))
	}
}

func TestExecute_LimitsGatePreservesLegacyHash(t *testing.T) {
	legacy, err := proto.MarshalOptions{Deterministic: true}.Marshal(testExecution())
	require.NoError(t, err)
	legacyRequest := cctypes.ComputeRequest{PublicData: legacy}
	for _, g := range []settings.Getter{nil, &settings.Atomic{}, jsonGetter(t, `{}`)} {
		mock := &mockConfidentialAction{}
		action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
		input := testExecution()
		input.Limits = &confworkflowtypes.ExecutionLimits{HttpAction: &confworkflowtypes.HTTPActionLimits{CallLimit: proto.Uint32(1)}}
		metadata := testMetadata()
		metadata.ExecutionTimestamp = limitsTimestamp
		_, capErr := action.Execute(t.Context(), metadata, &confworkflowtypes.ConfidentialWorkflowRequest{Execution: input})
		require.Nil(t, capErr)
		require.Nil(t, mock.executed.Execution.Limits, "caller-supplied limits cannot bypass activation")
		got, err := proto.MarshalOptions{Deterministic: true}.Marshal(mock.executed.GetInput())
		require.NoError(t, err)
		assert.Equal(t, legacy, got)
		req := cctypes.ComputeRequest{PublicData: got}
		assert.Equal(t, legacyRequest.Hash(), req.Hash())
	}
}

func TestExecute_LimitsGateSettingsDelivery(t *testing.T) {
	g := &settings.Atomic{}
	var encoded [][]byte
	execute := func(ts time.Time) *confworkflowtypes.ExecutionLimits {
		mock := &mockConfidentialAction{}
		action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
		metadata := testMetadata()
		metadata.ExecutionTimestamp = ts
		_, capErr := action.Execute(t.Context(), metadata, &confworkflowtypes.ConfidentialWorkflowRequest{Execution: testExecution()})
		require.Nil(t, capErr)
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(mock.executed.GetInput())
		require.NoError(t, err)
		encoded = append(encoded, b)
		return mock.executed.Execution.Limits
	}

	assert.Nil(t, execute(limitsTimestamp))
	require.NoError(t, g.Store(settings.Snapshot{Settings: `
[global.PerWorkflow]
FeatureConfidentialWorkflowExecutionLimitsActivePeriod = '` + limitsWindow + `'
[owner.1234567890abcdef1234567890abcdef12345678.PerWorkflow.HTTPAction]
CallLimit = '20'
RequestSizeLimit = '200kb'
`}))
	got := execute(limitsTimestamp)
	require.NotNil(t, got)
	assert.Equal(t, uint32(20), got.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(200_000), got.GetHttpAction().GetRequestSizeLimitBytes())
	execute(limitsTimestamp.In(time.FixedZone("other node", -5*60*60)))
	assert.Equal(t, encoded[1], encoded[2])
	onRequest := cctypes.ComputeRequest{PublicData: encoded[1]}
	otherNodeRequest := cctypes.ComputeRequest{PublicData: encoded[2]}
	assert.Equal(t, onRequest.Hash(), otherNodeRequest.Hash())
	assert.NotEqual(t, encoded[0], encoded[1])
	// A later settings update cannot change the already serialized request.
	require.NoError(t, g.Store(settings.Snapshot{Settings: "[global.PerWorkflow]\n"}))
	assert.Nil(t, execute(limitsTimestamp))
	assert.Equal(t, encoded[0], encoded[3])
	var previous confworkflowtypes.WorkflowExecution
	require.NoError(t, proto.Unmarshal(encoded[1], &previous))
	assert.Equal(t, uint32(20), previous.GetLimits().GetHttpAction().GetCallLimit())
}
