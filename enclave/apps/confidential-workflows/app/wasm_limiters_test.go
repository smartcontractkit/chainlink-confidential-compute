package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestWASMModuleLimiters_Defaults(t *testing.T) {
	defaults := cresettings.Default.PerWorkflow
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	moduleLimiters := newWASMModuleLimiters(ctx, logger.Test(t), nil)
	t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })

	cfg := &host.ModuleConfig{}
	moduleLimiters.apply(cfg)
	require.NotNil(t, cfg.MemoryLimiter)
	require.NotNil(t, cfg.MaxCompressedBinaryLimiter)
	require.NotNil(t, cfg.MaxDecompressedBinaryLimiter)
	require.NotNil(t, cfg.MaxResponseSizeLimiter)
	require.NotNil(t, cfg.PendingCallsLimiter)
	require.NotNil(t, cfg.EnableUserMetricsLimiter)
	require.NotNil(t, cfg.MaxUserMetricPayloadLimiter)
	require.NotNil(t, cfg.MaxUserMetricNameLengthLimiter)
	require.NotNil(t, cfg.MaxUserMetricLabelsPerMetricLimiter)
	require.NotNil(t, cfg.MaxUserMetricLabelValueLengthLimiter)
	require.NotNil(t, cfg.MaxSubscriptionsLimiter)
	assert.Equal(t, uint32(defaults.LogLineLimit.DefaultValue), cfg.MaxLogLenBytes)

	memory, err := cfg.MemoryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaults.WASMMemoryLimit.DefaultValue, memory)
	compressed, err := cfg.MaxCompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaults.WASMCompressedBinarySizeLimit.DefaultValue, compressed)
	decompressed, err := cfg.MaxDecompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaults.WASMBinarySizeLimit.DefaultValue, decompressed)
	response, err := cfg.MaxResponseSizeLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaults.ExecutionResponseLimit.DefaultValue, response)
	pendingCalls, err := cfg.PendingCallsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 30, pendingCalls)
	userMetricsEnabled, err := cfg.EnableUserMetricsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.False(t, userMetricsEnabled)
	metricPayload, err := cfg.MaxUserMetricPayloadLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaults.UserMetricPayloadLimit.DefaultValue, metricPayload)
	metricName, err := cfg.MaxUserMetricNameLengthLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 128, metricName)
	metricLabels, err := cfg.MaxUserMetricLabelsPerMetricLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 10, metricLabels)
	metricLabelValue, err := cfg.MaxUserMetricLabelValueLengthLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 256, metricLabelValue)
	subscriptions, err := cfg.MaxSubscriptionsLimiter.Limit(ctx)
	require.NoError(t, err)
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
	moduleLimiters := newWASMModuleLimiters(ctx, a.logger, a.limiterSettings.Snapshot())
	t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })
	cfg := &host.ModuleConfig{}
	moduleLimiters.apply(cfg)
	assert.Equal(t, uint32(2*config.KByte), cfg.MaxLogLenBytes)

	memory, err := cfg.MemoryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, config.Size(256)*config.MByte, memory)
	compressed, err := cfg.MaxCompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, config.Size(11)*config.MByte, compressed)
	decompressed, err := cfg.MaxDecompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, config.Size(12)*config.MByte, decompressed)
	response, err := cfg.MaxResponseSizeLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, config.Size(13)*config.KByte, response)
	pendingCalls, err := cfg.PendingCallsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 7, pendingCalls)
	userMetricsEnabled, err := cfg.EnableUserMetricsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.True(t, userMetricsEnabled)
	metricPayload, err := cfg.MaxUserMetricPayloadLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, config.Size(14)*config.KByte, metricPayload)
	metricName, err := cfg.MaxUserMetricNameLengthLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 15, metricName)
	metricLabels, err := cfg.MaxUserMetricLabelsPerMetricLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 16, metricLabels)
	metricLabelValue, err := cfg.MaxUserMetricLabelValueLengthLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 17, metricLabelValue)
	subscriptions, err := cfg.MaxSubscriptionsLimiter.Limit(ctx)
	require.NoError(t, err)
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
		moduleLimiters := newWASMModuleLimiters(ctx, a.logger, a.limiterSettings.Snapshot())
		defer func() { require.NoError(t, moduleLimiters.Close()) }()
		limit, err := moduleLimiters.memory.Limit(ctx)
		require.NoError(t, err)
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
			moduleLimiters := newWASMModuleLimiters(ctx, logger.Test(t), source.Snapshot())
			t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })

			got, err := moduleLimiters.memory.Limit(ctx)
			require.NoError(t, err)
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

			moduleLimiters := newWASMModuleLimiters(ctx, logger.Test(t), source.Snapshot())
			t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })
			cfg := &host.ModuleConfig{}
			moduleLimiters.apply(cfg)

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
			l := newWASMModuleLimiters(ctx, lggr, &limiterSettingsSnapshot{getter: getter})
			t.Cleanup(func() { require.NoError(t, l.Close()) })
			got, err := l.memory.Limit(ctx)
			require.NoError(t, err)
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
	l := newWASMModuleLimiters(ctx, logger.Test(t), source.Snapshot())
	t.Cleanup(func() { require.NoError(t, l.Close()) })
	for range 2 {
		memory, err := l.memory.Limit(ctx)
		require.NoError(t, err)
		assert.Equal(t, 256*config.MByte, memory)
		pendingCalls, err := l.pendingCalls.Limit(ctx)
		require.NoError(t, err)
		assert.Equal(t, 7, pendingCalls)
		assert.Equal(t, uint32(2*config.KByte), l.maxLogLenBytes)
	}
	require.Len(t, calls, 12)
	for key, count := range calls {
		assert.Equal(t, 1, count, key)
	}
	next := newWASMModuleLimiters(ctx, logger.Test(t), source.Snapshot())
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	memory, err := next.memory.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue, memory)
	assert.Equal(t, uint32(cresettings.Default.PerWorkflow.LogLineLimit.DefaultValue), next.maxLogLenBytes)
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
				l := newWASMModuleLimiters(ctx, lggr, source.Snapshot())
				defer func() { assert.NoError(t, l.Close()) }()
				memory, err := l.memory.Limit(ctx)
				assert.NoError(t, err)
				assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.DefaultValue, memory)
			})
		}
		wg.Wait()
		assert.Equal(t, generation, logs.Len())
	}
	assert.Equal(t, cresettings.Default.PerWorkflow.WASMMemoryLimit.Key, logs.All()[0].ContextMap()["key"])
}

func TestWASMModuleLimiters_PendingCallsAndClose(t *testing.T) {
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	for _, used := range []bool{false, true} {
		t.Run(fmt.Sprintf("used=%t", used), func(t *testing.T) {
			l := newWASMModuleLimiters(ctx, logger.Test(t), nil)
			if used {
				limit := cresettings.Default.PerWorkflow.CapabilityConcurrencyLimit.DefaultValue
				require.NoError(t, l.pendingCalls.Use(ctx, limit))
				err := l.pendingCalls.Use(ctx, 1)
				require.ErrorContains(t, err, "resource limited for workflow[workflow]")
				require.NoError(t, l.pendingCalls.Free(ctx, limit))
				free, err := l.pendingCalls.Wait(ctx, 1)
				require.NoError(t, err)
				free()
			}
			done := make(chan error, 1)
			go func() { done <- l.Close() }()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("limiter Close blocked")
			}
		})
	}
}
