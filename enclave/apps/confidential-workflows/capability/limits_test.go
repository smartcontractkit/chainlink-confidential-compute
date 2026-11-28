package capability

import (
	"context"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	overrideOwner = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	plainOwner    = "70997970c51812dc3a010c7d01b50e0d17dc79c8"
)

func jsonGetter(t *testing.T, doc string) settings.Getter {
	t.Helper()
	g, err := settings.NewJSONGetter([]byte(doc))
	require.NoError(t, err)
	return g
}

func creCtx(org, owner, workflow string) context.Context {
	return contexts.WithCRE(context.Background(), contexts.CRE{Org: org, Owner: owner, Workflow: workflow})
}

func resolve(t *testing.T, g settings.Getter, ctx context.Context) *confworkflowtypes.ExecutionLimits {
	t.Helper()
	got, err := resolveExecutionLimits(ctx, g, logger.Sugared(logger.Test(t)))
	require.NoError(t, err)
	return got
}

// With inclusion enabled and no limit overrides, the CRE defaults are sent.
func TestResolveExecutionLimits_SendsDefaults(t *testing.T) {
	got := resolve(t, jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"}}}}`), creCtx("org-1", plainOwner, "wf-1"))
	require.NotNil(t, got)
	assert.Equal(t, uint32(5), got.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(10_000), got.GetHttpAction().GetRequestSizeLimitBytes())
	assert.Equal(t, uint64(100_000), got.GetHttpAction().GetResponseSizeLimitBytes())
	assert.Equal(t, 10*time.Second, got.GetHttpAction().GetConnectionTimeout().AsDuration())

	w := got.GetWasm()
	assert.Equal(t, uint64(100_000_000), w.GetMemoryLimitBytes())
	assert.Equal(t, 5*time.Minute, w.GetExecutionTimeout().AsDuration())
	require.NotNil(t, w.ResponseLimitEnforced)
	assert.False(t, w.GetResponseLimitEnforced())
	assert.Equal(t, uint32(30), w.GetCapabilityConcurrencyLimit())
	assert.Equal(t, uint64(1000), w.GetLogLineLimitBytes())
	assert.Equal(t, uint32(1000), w.GetLogEventLimit())
	require.NotNil(t, w.UserMetricEnabled)
	assert.False(t, w.GetUserMetricEnabled())
	assert.Equal(t, uint64(4000), w.GetUserMetricPayloadLimitBytes())
	assert.Equal(t, uint32(128), w.GetUserMetricNameLengthLimit())
	assert.Equal(t, uint32(20), w.GetUserMetricLabelsPerMetric())
	assert.Equal(t, uint32(256), w.GetUserMetricLabelValueLength())
}

// Scoped overrides resolve exactly as in the engine: workflow over owner over
// org over global, with unset values taking the CRE default.
func TestResolveExecutionLimits_ScopePrecedence(t *testing.T) {
	g := jsonGetter(t, `{
		"global": {"PerWorkflow": {"ConfidentialWorkflows": {"IncludeExecutionLimits": "true"}, "CapabilityConcurrencyLimit": "31"}},
		"org": {"org-1": {"PerWorkflow": {"HTTPAction": {"CallLimit": "30"}, "UserMetricEnabled": "true"}}},
		"owner": {"`+overrideOwner+`": {"PerWorkflow": {"HTTPAction": {"CallLimit": "20", "RequestSizeLimit": "200kb"}}}},
		"workflow": {"wf-1": {"PerWorkflow": {"HTTPAction": {"ConnectionTimeout": "5s"}}}}
	}`)

	got := resolve(t, g, creCtx("org-1", overrideOwner, "wf-1"))
	assert.Equal(t, uint32(20), got.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(200_000), got.GetHttpAction().GetRequestSizeLimitBytes())
	assert.Equal(t, 5*time.Second, got.GetHttpAction().GetConnectionTimeout().AsDuration())
	assert.True(t, got.GetWasm().GetUserMetricEnabled())
	assert.Equal(t, uint32(31), got.GetWasm().GetCapabilityConcurrencyLimit())

	got = resolve(t, g, creCtx("org-1", plainOwner, "wf-2"))
	assert.Equal(t, uint32(30), got.GetHttpAction().GetCallLimit())
	assert.Equal(t, uint64(10_000), got.GetHttpAction().GetRequestSizeLimitBytes())

	got = resolve(t, g, creCtx("org-2", plainOwner, "wf-3"))
	assert.Equal(t, uint32(5), got.GetHttpAction().GetCallLimit())
	assert.False(t, got.GetWasm().GetUserMetricEnabled())
}

// An invalid override must not become the default: the limit is left unset,
// so the enclave applies nothing for it.
func TestResolveExecutionLimits_InvalidValueLeavesLimitUnset(t *testing.T) {
	g := jsonGetter(t, `{
		"global": {"PerWorkflow": {"ConfidentialWorkflows": {"IncludeExecutionLimits": "true"}}},
		"owner": {"`+overrideOwner+`": {"PerWorkflow": {
			"HTTPAction": {"CallLimit": "-1", "RequestSizeLimit": "lots"},
			"UserMetricEnabled": "maybe"
		}}}
	}`)
	got := resolve(t, g, creCtx("org-1", overrideOwner, "wf-1"))
	require.NotNil(t, got)
	assert.Nil(t, got.GetHttpAction().CallLimit)
	assert.Nil(t, got.GetHttpAction().RequestSizeLimitBytes)
	assert.NotNil(t, got.GetHttpAction().ResponseSizeLimitBytes)
	assert.Nil(t, got.GetWasm().UserMetricEnabled)
	assert.NotNil(t, got.GetWasm().LogEventLimit)
}

// Every node must sign identical PublicData, so resolution and marshaling
// must be deterministic.
func TestResolveExecutionLimits_Deterministic(t *testing.T) {
	g := jsonGetter(t, `{"global":{"PerWorkflow":{"ConfidentialWorkflows":{"IncludeExecutionLimits":"true"}}},"owner": {"`+overrideOwner+`": {"PerWorkflow": {"HTTPAction": {"CallLimit": "20"}}}}}`)
	marshal := func() []byte {
		e := testExecution()
		e.Limits = resolve(t, g, creCtx("org-1", overrideOwner, "wf-1"))
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
		require.NoError(t, err)
		return b
	}
	assert.Equal(t, marshal(), marshal())
}

func TestExecute_SendsResolvedLimits(t *testing.T) {
	mock := &mockConfidentialAction{}
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: mock,
		lggr:               logger.Sugared(logger.Test(t)),
		settings: jsonGetter(t, `{
			"global": {"PerWorkflow": {"ConfidentialWorkflows": {"IncludeExecutionLimits": "true"}}},
			"owner": {"1234567890abcdef1234567890abcdef12345678": {"PerWorkflow": {"HTTPAction": {"CallLimit": "20"}}}}
		}`),
	}
	metadata := testMetadata()
	input := testExecution()
	input.Limits = &confworkflowtypes.ExecutionLimits{HttpAction: &confworkflowtypes.HTTPActionLimits{CallLimit: proto.Uint32(99)}}
	_, capErr := action.Execute(context.Background(), metadata, &confworkflowtypes.ConfidentialWorkflowRequest{Execution: input})
	require.Nil(t, capErr)
	require.NotNil(t, mock.executed)
	limits := mock.executed.Execution.GetLimits()
	require.NotNil(t, limits)
	assert.Equal(t, uint32(20), limits.GetHttpAction().GetCallLimit(), "the metadata's owner scope must reach the resolver")
	assert.NotNil(t, limits.GetWasm())
}
