package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestWASMModuleLimiters_Defaults(t *testing.T) {
	defaults := cresettings.Default.PerWorkflow
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	moduleLimiters := resolveWASMLimits(ctx, logger.Test(t), nil)

	cfg := moduleLimiters

	assert.Equal(t, uint32(defaults.LogLineLimit.DefaultValue), cfg.MaxLogLenBytes)

	memory := cfg.Memory
	assert.Equal(t, defaults.WASMMemoryLimit.DefaultValue, memory)
	compressed := cfg.MaxCompressedBinary
	assert.Equal(t, defaults.WASMCompressedBinarySizeLimit.DefaultValue, compressed)
	decompressed := cfg.MaxDecompressedBinary
	assert.Equal(t, defaults.WASMBinarySizeLimit.DefaultValue, decompressed)
	response := cfg.MaxResponseSize
	assert.Equal(t, defaults.ExecutionResponseLimit.DefaultValue, response)
	pendingCalls := cfg.PendingCalls
	assert.Equal(t, 30, pendingCalls)
	userMetricsEnabled := cfg.EnableUserMetrics
	assert.False(t, userMetricsEnabled)
	metricPayload := cfg.MaxUserMetricPayload
	assert.Equal(t, defaults.UserMetricPayloadLimit.DefaultValue, metricPayload)
	metricName := cfg.MaxUserMetricNameLength
	assert.Equal(t, 128, metricName)
	metricLabels := cfg.MaxUserMetricLabels
	assert.Equal(t, 10, metricLabels)
	metricLabelValue := cfg.MaxUserMetricLabelValueLen
	assert.Equal(t, 256, metricLabelValue)
	subscriptions := cfg.MaxSubscriptions
	assert.Equal(t, 128, subscriptions)
}

func TestWASMModuleLimiters_InjectedOverrides(t *testing.T) {
	a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t)).(*confidentialWorkflowsApp)
	req := testSettings("127.0.0.1:1")
	req.CRESettings = json.RawMessage(`{
		"global": {
			"WASMPollOneoffSubscriptionLimit": "64"
		},
		"workflow": {
			"workflow": {
				"PerWorkflow": {
					"WASMMemoryLimit": "256mb",
					"WASMCompressedBinarySizeLimit": "11mb",
					"WASMBinarySizeLimit": "12mb",
					"ExecutionResponseLimit": "13kb",
					"CapabilityConcurrencyLimit": "7",
					"LogLineLimit": "2kb",
					"UserMetricEnabled": "true",
					"UserMetricPayloadLimit": "14kb",
					"UserMetricNameLengthLimit": "15",
					"UserMetricLabelsPerMetric": "16",
					"UserMetricLabelValueLength": "17"
				}
			}
		}
	}`)
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	require.NoError(t, a.InjectSettings(raw))
	t.Cleanup(func() { require.NoError(t, a.storageFetcher.Close()) })

	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	moduleLimiters := resolveWASMLimits(ctx, a.logger, a.limiterSettings.Snapshot())

	cfg := moduleLimiters
	assert.Equal(t, uint32(2*config.KByte), cfg.MaxLogLenBytes)

	memory := cfg.Memory
	assert.Equal(t, config.Size(256)*config.MByte, memory)
	compressed := cfg.MaxCompressedBinary
	assert.Equal(t, config.Size(11)*config.MByte, compressed)
	decompressed := cfg.MaxDecompressedBinary
	assert.Equal(t, config.Size(12)*config.MByte, decompressed)
	response := cfg.MaxResponseSize
	assert.Equal(t, config.Size(13)*config.KByte, response)
	pendingCalls := cfg.PendingCalls
	assert.Equal(t, 7, pendingCalls)
	userMetricsEnabled := cfg.EnableUserMetrics
	assert.True(t, userMetricsEnabled)
	metricPayload := cfg.MaxUserMetricPayload
	assert.Equal(t, config.Size(14)*config.KByte, metricPayload)
	metricName := cfg.MaxUserMetricNameLength
	assert.Equal(t, 15, metricName)
	metricLabels := cfg.MaxUserMetricLabels
	assert.Equal(t, 16, metricLabels)
	metricLabelValue := cfg.MaxUserMetricLabelValueLen
	assert.Equal(t, 17, metricLabelValue)
	subscriptions := cfg.MaxSubscriptions
	assert.Equal(t, 64, subscriptions)
}

func TestInjectSettings_LimiterSettings(t *testing.T) {
	newApp := func() *confidentialWorkflowsApp {
		return NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t)).(*confidentialWorkflowsApp)
	}
	inject := func(t *testing.T, a *confidentialWorkflowsApp, creSettings json.RawMessage) error {
		t.Helper()
		req := testSettings("127.0.0.1:1")
		req.CRESettings = creSettings
		raw, err := json.Marshal(req)
		require.NoError(t, err)
		return a.InjectSettings(raw)
	}
	memoryLimit := func(t *testing.T, a *confidentialWorkflowsApp) config.Size {
		t.Helper()
		ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
		moduleLimiters := resolveWASMLimits(ctx, a.logger, a.limiterSettings.Snapshot())

		limit := moduleLimiters.Memory
		return limit
	}

	t.Run("malformed payload", func(t *testing.T) {
		err := inject(t, newApp(), json.RawMessage(`[]`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing CRE settings")
	})

	t.Run("omitted payload clears prior overrides", func(t *testing.T) {
		a := newApp()
		require.NoError(t, inject(t, a, json.RawMessage(`{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"256mb"}}}}`)))
		assert.Equal(t, config.Size(256)*config.MByte, memoryLimit(t, a))

		require.NoError(t, inject(t, a, nil))
		t.Cleanup(func() { require.NoError(t, a.storageFetcher.Close()) })
		assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue, memoryLimit(t, a))
	})
}

func TestWASMModuleLimiters_InvalidOrUnreachableOverrideUsesDefault(t *testing.T) {
	defaultMemoryLimit := cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue
	tests := []struct {
		name string
		raw  string
		cre  contexts.CRE
		want config.Size
	}{
		{
			name: "workflow override without owner",
			raw:  `{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"256mb"}}}}`,
			cre:  contexts.CRE{Workflow: "workflow"},
			want: defaultMemoryLimit,
		},
		{
			name: "global override without owner",
			raw:  `{"global":{"PerWorkflow":{"WASMMemoryLimit":"256mb"}}}`,
			cre:  contexts.CRE{Workflow: "workflow"},
			want: defaultMemoryLimit,
		},
		{
			name: "org override without owner",
			raw:  `{"global":{"PerWorkflow":{"WASMMemoryLimit":"64mb"}},"org":{"org":{"PerWorkflow":{"WASMMemoryLimit":"96mb"}}}}`,
			cre:  contexts.CRE{Org: "org", Workflow: "workflow"},
			want: defaultMemoryLimit,
		},
		{
			name: "invalid value",
			raw:  `{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"banana"}}}}`,
			cre:  contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"},
			want: defaultMemoryLimit,
		},
		{
			name: "sub-megabyte memory limit",
			raw:  `{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"512kb"}}}}`,
			cre:  contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"},
			want: defaultMemoryLimit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(test.raw))
			require.NoError(t, err)
			source := &mutableSettings{}
			source.SetGetter(getter)
			ctx := contexts.WithCRE(t.Context(), test.cre)
			moduleLimiters := resolveWASMLimits(ctx, logger.Test(t), source.Snapshot())

			got := moduleLimiters.Memory
			assert.Equal(t, test.want, got)
		})
	}
}

func TestWASMModuleLimiters_InvalidLogLineLimitUsesDefault(t *testing.T) {
	for _, value := range []string{"banana", "0b", "3gb"} {
		t.Run(value, func(t *testing.T) {
			getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(fmt.Sprintf(
				`{"workflow":{"workflow":{"PerWorkflow":{"LogLineLimit":%q}}}}`, value,
			)))
			require.NoError(t, err)
			source := &mutableSettings{}
			source.SetGetter(getter)
			ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})

			moduleLimiters := resolveWASMLimits(ctx, logger.Test(t), source.Snapshot())

			cfg := moduleLimiters

			assert.Equal(t, uint32(cresettings.Default.PerWorkflow.LogLineLimit.DefaultValue), cfg.MaxLogLenBytes)
		})
	}
}

func TestWASMModuleLimiters_ScopeResolution(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{
		"global":{"PerWorkflow":{"WASMMemoryLimit":"200mb"}},
		"org":{"org":{"PerWorkflow":{"WASMMemoryLimit":"201mb"}}},
		"owner":{"owner":{"PerWorkflow":{"WASMMemoryLimit":"202mb"}}},
		"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"203mb"}}}
	}`))
	require.NoError(t, err)
	for _, test := range []struct {
		name string
		cre  contexts.CRE
		want config.Size
	}{
		{"workflow", contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"}, 203 * config.MByte},
		{"owner", contexts.CRE{Org: "org", Owner: "owner", Workflow: "other"}, 202 * config.MByte},
		{"org", contexts.CRE{Org: "org", Owner: "other", Workflow: "other"}, 201 * config.MByte},
		{"global without org", contexts.CRE{Owner: "other", Workflow: "other"}, 200 * config.MByte},
	} {
		t.Run(test.name, func(t *testing.T) {
			lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
			ctx := contexts.WithCRE(t.Context(), test.cre)
			l := resolveWASMLimits(ctx, lggr, &limiterSettingsSnapshot{getter: getter})

			got := l.Memory
			assert.Equal(t, test.want, got)
			assert.Zero(t, logs.Len())
		})
	}
}

type settingsGetterFunc func(context.Context, settings.Scope, string) (string, error)

func (f settingsGetterFunc) GetScoped(ctx context.Context, scope settings.Scope, key string) (string, error) {
	return f(ctx, scope, key)
}

func TestWASMModuleLimiters_Snapshot(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{"global":{"PerWorkflow":{
		"WASMMemoryLimit":"256mb", "LogLineLimit":"2kb", "CapabilityConcurrencyLimit":"7"
	}}}`))
	require.NoError(t, err)
	source := &mutableSettings{}
	calls := make(map[string]int)
	source.SetGetter(settingsGetterFunc(func(ctx context.Context, scope settings.Scope, key string) (string, error) {
		calls[key]++
		// Replace settings during resolution; all values must still come from
		// the captured getter, even those read after the replacement.
		source.SetGetter(nil)
		return getter.GetScoped(ctx, scope, key)
	}))
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	l := resolveWASMLimits(ctx, logger.Test(t), source.Snapshot())

	for range 2 {
		memory := l.Memory
		assert.Equal(t, 256*config.MByte, memory)
		pendingCalls := l.PendingCalls
		assert.Equal(t, 7, pendingCalls)
		assert.Equal(t, uint32(2*config.KByte), l.MaxLogLenBytes)
	}
	require.Len(t, calls, 12)
	for key, count := range calls {
		assert.Equal(t, 1, count, key)
	}
	next := resolveWASMLimits(ctx, logger.Test(t), source.Snapshot())

	memory := next.Memory
	assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue, memory)
	assert.Equal(t, uint32(cresettings.Default.PerWorkflow.LogLineLimit.DefaultValue), next.MaxLogLenBytes)
}

func TestWASMModuleLimiters_FallbackLogsBoundedPerInjection(t *testing.T) {
	getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(`{"global":{"PerWorkflow":{"WASMMemoryLimit":"banana"}}}`))
	require.NoError(t, err)
	source := &mutableSettings{}
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	for generation := 1; generation <= 2; generation++ {
		source.SetGetter(getter)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				l := resolveWASMLimits(ctx, lggr, source.Snapshot())

				memory := l.Memory
				assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue, memory)
			})
		}
		wg.Wait()
		assert.Equal(t, generation, logs.Len())
	}
	assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.Key, logs.All()[0].ContextMap()["key"])
}
