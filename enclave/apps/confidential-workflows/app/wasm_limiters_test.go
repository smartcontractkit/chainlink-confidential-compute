package app

import (
	"encoding/json"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWASMModuleLimiters_Defaults(t *testing.T) {
	moduleLimiters, err := newWASMModuleLimiters(limits.Factory{Logger: logger.Test(t)})
	require.NoError(t, err)
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

	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	memory, err := cfg.MemoryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaultWASMMemoryLimit, memory)
	compressed, err := cfg.MaxCompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaultWASMCompressedBinaryLimit, compressed)
	decompressed, err := cfg.MaxDecompressedBinaryLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaultWASMDecompressedBinaryLimit, decompressed)
	response, err := cfg.MaxResponseSizeLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaultWASMResponseLimit, response)
	pendingCalls, err := cfg.PendingCallsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, 30, pendingCalls)
	userMetricsEnabled, err := cfg.EnableUserMetricsLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.False(t, userMetricsEnabled)
	metricPayload, err := cfg.MaxUserMetricPayloadLimiter.Limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, defaultUserMetricPayloadLimit, metricPayload)
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

	moduleLimiters, err := newWASMModuleLimiters(limits.Factory{Logger: a.logger, Settings: a.limiterSettings})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })
	cfg := &host.ModuleConfig{}
	moduleLimiters.apply(cfg)
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})

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
		moduleLimiters, err := newWASMModuleLimiters(limits.Factory{Logger: a.logger, Settings: a.limiterSettings})
		require.NoError(t, err)
		defer func() { require.NoError(t, moduleLimiters.Close()) }()
		ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
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
		assert.Equal(t, defaultWASMMemoryLimit, memoryLimit(t, a))
	})
}

func TestWASMModuleLimiterSettingParsers(t *testing.T) {
	cfg := cresettings.Default.PerWorkflow
	want := []string{
		cfg.WASMMemoryLimit.Key,
		cfg.WASMCompressedBinarySizeLimit.Key,
		cfg.WASMBinarySizeLimit.Key,
		cfg.ExecutionResponseLimit.Key,
		cfg.CapabilityConcurrencyLimit.Key,
		cfg.UserMetricEnabled.Key,
		cfg.UserMetricPayloadLimit.Key,
		cfg.UserMetricNameLengthLimit.Key,
		cfg.UserMetricLabelsPerMetric.Key,
		cfg.UserMetricLabelValueLength.Key,
		cresettings.Default.WASMPollOneoffSubscriptionLimit.Key,
	}
	got := make([]string, 0, len(wasmLimiterSettingParsers()))
	for key := range wasmLimiterSettingParsers() {
		got = append(got, key)
	}
	assert.ElementsMatch(t, want, got)
}

func TestWASMModuleLimiters_InvalidOrUnreachableOverrideUsesDefault(t *testing.T) {
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
			want: defaultWASMMemoryLimit,
		},
		{
			name: "global override without owner",
			raw:  `{"global":{"PerWorkflow":{"WASMMemoryLimit":"256mb"}}}`,
			cre:  contexts.CRE{Workflow: "workflow"},
			want: config.Size(256) * config.MByte,
		},
		{
			name: "org override without owner",
			raw:  `{"global":{"PerWorkflow":{"WASMMemoryLimit":"64mb"}},"org":{"org":{"PerWorkflow":{"WASMMemoryLimit":"96mb"}}}}`,
			cre:  contexts.CRE{Org: "org", Workflow: "workflow"},
			want: config.Size(96) * config.MByte,
		},
		{
			name: "invalid value",
			raw:  `{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"banana"}}}}`,
			cre:  contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"},
			want: defaultWASMMemoryLimit,
		},
		{
			name: "sub-megabyte memory limit",
			raw:  `{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"512kb"}}}}`,
			cre:  contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"},
			want: defaultWASMMemoryLimit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getter, err := (settings.GetterConfig{}).NewJSONGetter([]byte(test.raw))
			require.NoError(t, err)
			source := newMutableSettings(logger.Test(t))
			source.SetGetter(getter)
			moduleLimiters, err := newWASMModuleLimiters(limits.Factory{Logger: logger.Test(t), Settings: source})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, moduleLimiters.Close()) })

			got, err := moduleLimiters.memory.Limit(contexts.WithCRE(t.Context(), test.cre))
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
