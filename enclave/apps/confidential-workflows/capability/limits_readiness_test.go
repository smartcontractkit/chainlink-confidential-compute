package capability

import (
	"context"
	"errors"
	"testing"

	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestExecute_RequiresLoadedSettings(t *testing.T) {
	for name, g := range map[string]settings.Getter{
		"nil":          nil,
		"zero atomic":  &settings.Atomic{},
		"LOOP startup": loop.NewAtomicSettings(nil),
		"typed nil":    (*settings.Atomic)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfidentialAction{}
			action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
			input := testExecution()
			input.Limits = &confworkflowtypes.ExecutionLimits{HttpAction: &confworkflowtypes.HTTPActionLimits{CallLimit: proto.Uint32(99)}}
			_, capErr := action.Execute(t.Context(), testMetadata(), &confworkflowtypes.ConfidentialWorkflowRequest{Execution: input})
			require.NotNil(t, capErr)
			assert.Equal(t, caperrors.OriginSystem, capErr.Origin())
			assert.Equal(t, caperrors.Unavailable, capErr.Code())
			assert.Contains(t, capErr.Error(), "CRE settings not loaded")
			assert.Nil(t, mock.executed, "unready signers must not reach serialization/signing")
		})
	}
}

func TestExecute_InclusionOffPreservesLegacyHash(t *testing.T) {
	jd := loop.NewAtomicSettings(nil)
	require.NoError(t, jd.Store(settings.Snapshot{}))
	legacy, err := proto.MarshalOptions{Deterministic: true}.Marshal(testExecution())
	require.NoError(t, err)
	legacyRequest := cctypes.ComputeRequest{PublicData: legacy}
	for name, g := range map[string]settings.Getter{
		"static":       jsonGetter(t, `{}`),
		"env":          loop.NewAtomicSettings(jsonGetter(t, `{}`)),
		"JD":           jd,
		"explicit off": jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"false"},"HTTPAction":{"CallLimit":"20"}}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfidentialAction{}
			action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
			input := testExecution()
			input.Limits = &confworkflowtypes.ExecutionLimits{HttpAction: &confworkflowtypes.HTTPActionLimits{CallLimit: proto.Uint32(99)}}
			metadata := testMetadata()
			require.True(t, metadata.ExecutionTimestamp.IsZero())
			_, capErr := action.Execute(t.Context(), metadata, &confworkflowtypes.ConfidentialWorkflowRequest{Execution: input})
			require.Nil(t, capErr)
			require.NotNil(t, mock.executed)
			assert.Nil(t, mock.executed.Execution.Limits, "off must discard caller-supplied limits")
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(mock.executed.GetInput())
			require.NoError(t, err)
			assert.Equal(t, legacy, encoded)
			request := cctypes.ComputeRequest{PublicData: encoded}
			assert.Equal(t, legacyRequest.Hash(), request.Hash())
		})
	}
}

func TestExecute_SettingsDelivery(t *testing.T) {
	g := loop.NewAtomicSettings(jsonGetter(t, `{}`))
	execute := func() ([]byte, *confworkflowtypes.ExecutionLimits) {
		mock := &mockConfidentialAction{}
		action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
		_, capErr := action.Execute(t.Context(), testMetadata(), &confworkflowtypes.ConfidentialWorkflowRequest{Execution: testExecution()})
		require.Nil(t, capErr)
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(mock.executed.GetInput())
		require.NoError(t, err)
		return b, mock.executed.Execution.Limits
	}
	offBytes, offLimits := execute()
	assert.Nil(t, offLimits)
	g.SetGetter(jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"},"HTTPAction":{"CallLimit":"20","RequestSizeLimit":"200kb"}}}}`))
	envBytes, envLimits := execute()
	assert.NotEqual(t, offBytes, envBytes)
	assert.Equal(t, uint32(20), envLimits.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(200_000), envLimits.GetHttpAction().GetRequestSizeLimitBytes())
	require.NoError(t, g.Store(settings.Snapshot{Settings: "[global.PerWorkflow.ConfidentialWorkflows]\nIncludeExecutionLimits = 'true'\n[global.PerWorkflow.HTTPAction]\nCallLimit = '2'"}))
	jdBytes, jdLimits := execute()
	assert.Equal(t, uint32(2), jdLimits.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(10_000), jdLimits.GetHttpAction().GetRequestSizeLimitBytes(), "JD replaces env rather than merging")
	assert.NotEqual(t, envBytes, jdBytes)
	require.Error(t, g.Store(settings.Snapshot{Settings: "[invalid"}))
	retained, _ := execute()
	assert.Equal(t, jdBytes, retained)
	// A fresh getter with equivalent settings must produce the same signed hash.
	g = loop.NewAtomicSettings(nil)
	require.NoError(t, g.Store(settings.Snapshot{Settings: "[global.PerWorkflow.ConfidentialWorkflows]\nIncludeExecutionLimits = 'true'\n[global.PerWorkflow.HTTPAction]\nCallLimit = '2'"}))
	otherBytes, _ := execute()
	assert.Equal(t, jdBytes, otherBytes)
	first := cctypes.ComputeRequest{PublicData: jdBytes}
	other := cctypes.ComputeRequest{PublicData: otherBytes}
	assert.Equal(t, first.Hash(), other.Hash())
	require.NoError(t, g.Store(settings.Snapshot{}))
	disabledBytes, disabled := execute()
	assert.Nil(t, disabled, "loaded snapshot without opt-in disables inclusion")
	assert.Equal(t, offBytes, disabledBytes, "disabling inclusion restores legacy bytes")
	var previous confworkflowtypes.WorkflowExecution
	require.NoError(t, proto.Unmarshal(envBytes, &previous))
	assert.Equal(t, uint32(20), previous.GetLimits().GetHttpAction().GetCallLimit())
	assert.Equal(t, uint32(20), envLimits.GetHttpAction().GetCallLimit())
}

type limitGetterFunc func(context.Context, settings.Scope, string) (string, error)

func (f limitGetterFunc) GetScoped(ctx context.Context, scope settings.Scope, key string) (string, error) {
	return f(ctx, scope, key)
}

func TestExecute_InvalidInclusionGateDoesNotDispatch(t *testing.T) {
	for name, g := range map[string]settings.Getter{
		"malformed": jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"invalid"}}}}`),
		"read failure": limitGetterFunc(func(context.Context, settings.Scope, string) (string, error) {
			return "true", errors.New("settings unavailable")
		}),
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfidentialAction{}
			action := &ConfidentialWorkflowAction{ConfidentialAction: mock, lggr: logger.Sugared(logger.Test(t)), settings: g}
			input := testExecution()
			input.Limits = &confworkflowtypes.ExecutionLimits{HttpAction: &confworkflowtypes.HTTPActionLimits{CallLimit: proto.Uint32(99)}}
			_, capErr := action.Execute(t.Context(), testMetadata(), &confworkflowtypes.ConfidentialWorkflowRequest{Execution: input})
			require.NotNil(t, capErr)
			assert.Equal(t, caperrors.OriginSystem, capErr.Origin())
			assert.Equal(t, caperrors.Unavailable, capErr.Code())
			assert.Contains(t, capErr.Error(), "PerWorkflow.ConfidentialWorkflows.IncludeExecutionLimits")
			assert.Nil(t, mock.executed)
		})
	}
}

func TestResolveExecutionLimits_InclusionScopePrecedence(t *testing.T) {
	g := jsonGetter(t, `{
		"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"false"}}},
		"org":{"org-1":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"}}}},
		"owner":{"`+overrideOwner+`":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"false"}}}},
		"workflow":{"wf-on":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"}}}}
	}`)
	for _, tc := range []struct {
		org, owner, workflow string
		want                 bool
	}{
		{"org-2", plainOwner, "wf-1", false},
		{"org-1", plainOwner, "wf-1", true},
		{"org-1", overrideOwner, "wf-1", false},
		{"org-1", overrideOwner, "wf-on", true},
	} {
		assert.Equal(t, tc.want, resolve(t, g, creCtx(tc.org, tc.owner, tc.workflow)) != nil)
	}
}

func TestResolveExecutionLimits_RequiresScopedOptIn(t *testing.T) {
	s := &cresettings.Default.PerWorkflow.ConfidentialWorkflows.IncludeExecutionLimits
	previous := s.DefaultValue
	s.DefaultValue = true // CL_CRE_SETTINGS_DEFAULT must not opt in a loaded empty snapshot.
	t.Cleanup(func() { s.DefaultValue = previous })
	assert.Nil(t, resolve(t, jsonGetter(t, `{}`), creCtx("org-1", plainOwner, "wf-1")))
}

type updatingGetter struct {
	settings.Getter
	update func()
}

func (g *updatingGetter) GetScoped(ctx context.Context, scope settings.Scope, key string) (string, error) {
	if g.update != nil {
		g.update()
		g.update = nil
	}
	return g.Getter.GetScoped(ctx, scope, key)
}

func TestResolveExecutionLimits_CapturesOneSource(t *testing.T) {
	g := loop.NewAtomicSettings(nil)
	g.SetGetter(&updatingGetter{
		Getter: jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"},"HTTPAction":{"CallLimit":"20","RequestSizeLimit":"200kb"}}}}`),
		update: func() {
			require.NoError(t, g.Store(settings.Snapshot{Settings: "[global.PerWorkflow.ConfidentialWorkflows]\nIncludeExecutionLimits = 'false'\n[global.PerWorkflow.HTTPAction]\nCallLimit = '2'\nRequestSizeLimit = '10kb'"}))
		},
	})
	ctx := creCtx("org-1", plainOwner, "wf-1")
	got := resolve(t, g, ctx)
	assert.Equal(t, uint32(20), got.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(200_000), got.GetHttpAction().GetRequestSizeLimitBytes())
	next := resolve(t, g, ctx)
	assert.Nil(t, next, "the next execution sees the new gate and limits source")
}

func TestResolveExecutionLimits_ExplicitZeroAndFalse(t *testing.T) {
	got := resolve(t, jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"},"HTTPAction":{"CallLimit":"0","RequestSizeLimit":"0b","ResponseSizeLimit":"0b","ConnectionTimeout":"0s"},"ExecutionResponseLimitEnforced":"false","CapabilityConcurrencyLimit":"0","UserMetricEnabled":"false"}}}`), creCtx("org-1", plainOwner, "wf-1"))
	h, w := got.GetHttpAction(), got.GetWasm()
	assert.Equal(t, proto.Uint32(0), h.CallLimit)
	assert.Equal(t, proto.Uint64(0), h.RequestSizeLimitBytes)
	assert.Equal(t, proto.Uint64(0), h.ResponseSizeLimitBytes)
	require.NotNil(t, h.ConnectionTimeout)
	assert.Zero(t, h.ConnectionTimeout.AsDuration())
	assert.Equal(t, proto.Bool(false), w.ResponseLimitEnforced)
	assert.Equal(t, proto.Bool(false), w.UserMetricEnabled)
	assert.Equal(t, proto.Uint32(0), w.CapabilityConcurrencyLimit)
}
