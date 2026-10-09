package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestHTTPActionLimits_DefaultsAndScopes(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{
		"global":{"PerWorkflow":{"HTTPAction":{"CallLimit":"6","ConnectionTimeout":"6s","RequestSizeLimit":"6kb","ResponseSizeLimit":"6kb"}}},
		"org":{"org":{"PerWorkflow":{"HTTPAction":{"CallLimit":"7","ConnectionTimeout":"7s","RequestSizeLimit":"7kb","ResponseSizeLimit":"7kb"}}}},
		"owner":{"owner":{"PerWorkflow":{"HTTPAction":{"CallLimit":"8","ConnectionTimeout":"8s","RequestSizeLimit":"8kb","ResponseSizeLimit":"8kb"}}}},
		"workflow":{"workflow":{"PerWorkflow":{"HTTPAction":{"CallLimit":"9","ConnectionTimeout":"9s","RequestSizeLimit":"9kb","ResponseSizeLimit":"9kb"}}}}
	}`))
	require.NoError(t, err)
	for _, tt := range []struct {
		name string
		cre  contexts.CRE
		want int
	}{
		{"workflow", contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"}, 9},
		{"owner", contexts.CRE{Org: "org", Owner: "owner", Workflow: "other"}, 8},
		{"org", contexts.CRE{Org: "org", Owner: "other", Workflow: "other"}, 7},
		{"global without org", contexts.CRE{Owner: "other", Workflow: "other"}, 6},
		{"missing owner", contexts.CRE{Org: "org", Workflow: "workflow"}, 0},
		{"missing workflow", contexts.CRE{Org: "org", Owner: "owner"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := contexts.WithCRE(t.Context(), tt.cre)
			got := newHTTPActionLimits(ctx, nil, &limiterSettingsSnapshot{getter: getter})
			if tt.want == 0 {
				assertHTTPDefaults(t, got)
				return
			}
			assert.Equal(t, httpActionLimits{callLimit: tt.want, fetch: httpfetch.Limits{
				ConnectionTimeout: time.Duration(tt.want) * time.Second,
				RequestSizeLimit:  config.Size(tt.want) * config.KByte,
				ResponseSizeLimit: config.Size(tt.want) * config.KByte,
			}}, got)
		})
	}
	assertHTTPDefaults(t, newHTTPActionLimits(t.Context(), nil, nil))
}

func assertHTTPDefaults(t *testing.T, got httpActionLimits) {
	t.Helper()
	cfg := cresettings.Default.PerWorkflow.HTTPAction
	assert.Equal(t, httpActionLimits{callLimit: cfg.CallLimit.DefaultValue, fetch: httpfetch.Limits{
		ConnectionTimeout: cfg.ConnectionTimeout.DefaultValue,
		RequestSizeLimit:  cfg.RequestSizeLimit.DefaultValue,
		ResponseSizeLimit: cfg.ResponseSizeLimit.DefaultValue,
	}}, got)
}

func TestHTTPActionLimits_Fallback(t *testing.T) {
	for _, value := range []string{"banana", "-1", ""} {
		t.Run(value, func(t *testing.T) {
			getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(fmt.Sprintf(`{"global":{"PerWorkflow":{"HTTPAction":{
				"CallLimit":%q,"ConnectionTimeout":%q,"RequestSizeLimit":%q,"ResponseSizeLimit":%q
			}}}}`, value, value, value, value)))
			require.NoError(t, err)
			lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
			snapshot := &limiterSettingsSnapshot{getter: getter}
			ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
			for range 2 {
				assertHTTPDefaults(t, newHTTPActionLimits(ctx, lggr, snapshot))
			}
			if value == "" {
				assert.Zero(t, logs.Len())
			} else {
				assert.Equal(t, 4, logs.Len(), "one fallback warning per setting per snapshot")
			}
		})
	}
}

func TestHTTPActionLimits_Snapshot(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{"global":{"PerWorkflow":{"HTTPAction":{"CallLimit":"0","ConnectionTimeout":"0s","RequestSizeLimit":"0b","ResponseSizeLimit":"0b"}}}}`))
	require.NoError(t, err)
	source := &mutableSettings{}
	source.SetGetter(getter)
	snapshot := source.Snapshot()
	source.SetGetter(nil)
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	assert.Equal(t, httpActionLimits{}, newHTTPActionLimits(ctx, nil, snapshot), "zero limits are enforced, not defaulted")
	assertHTTPDefaults(t, newHTTPActionLimits(ctx, nil, source.Snapshot()))
}

func TestHTTPActionLimits_InvalidTimeoutDoesNotDiscardOtherOverrides(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{"global":{"PerWorkflow":{"HTTPAction":{"ConnectionTimeout":"-1s","CallLimit":"1"}}}}`))
	require.NoError(t, err)
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	got := newHTTPActionLimits(ctx, nil, &limiterSettingsSnapshot{getter: getter})
	assert.Equal(t, 1, got.callLimit)
	assert.Equal(t, cresettings.Default.PerWorkflow.HTTPAction.ConnectionTimeout.DefaultValue, got.fetch.ConnectionTimeout)
}
