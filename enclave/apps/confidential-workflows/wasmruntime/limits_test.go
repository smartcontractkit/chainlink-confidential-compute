package wasmruntime

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkLimit[T comparable](t *testing.T, ctx context.Context, limit func(context.Context) (T, error), want T) {
	t.Helper()
	got, err := limit(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestResolvedModuleLimits(t *testing.T) {
	c := wasmlimits.Config{
		Memory: 256 * config.MByte, MaxCompressedBinary: 11 * config.MByte,
		MaxDecompressedBinary: 12 * config.MByte, MaxResponseSize: 13 * config.KByte,
		PendingCalls: 7, EnableUserMetrics: true, MaxUserMetricPayload: 14 * config.KByte,
		MaxUserMetricNameLength: 15, MaxUserMetricLabels: 16, MaxUserMetricLabelValueLen: 17,
		MaxSubscriptions: 64, MaxLogLenBytes: uint32(2 * config.KByte),
	}
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	l := newModuleConfig(c)
	t.Cleanup(func() { require.NoError(t, closeModuleLimiters(l)) })
	checkLimit(t, ctx, l.MemoryLimiter.Limit, c.Memory)
	checkLimit(t, ctx, l.MaxCompressedBinaryLimiter.Limit, c.MaxCompressedBinary)
	checkLimit(t, ctx, l.MaxDecompressedBinaryLimiter.Limit, c.MaxDecompressedBinary)
	checkLimit(t, ctx, l.MaxResponseSizeLimiter.Limit, c.MaxResponseSize)
	checkLimit(t, ctx, l.PendingCallsLimiter.Limit, c.PendingCalls)
	checkLimit(t, ctx, l.EnableUserMetricsLimiter.Limit, c.EnableUserMetrics)
	checkLimit(t, ctx, l.MaxUserMetricPayloadLimiter.Limit, c.MaxUserMetricPayload)
	checkLimit(t, ctx, l.MaxUserMetricNameLengthLimiter.Limit, c.MaxUserMetricNameLength)
	checkLimit(t, ctx, l.MaxUserMetricLabelsPerMetricLimiter.Limit, c.MaxUserMetricLabels)
	checkLimit(t, ctx, l.MaxUserMetricLabelValueLengthLimiter.Limit, c.MaxUserMetricLabelValueLen)
	checkLimit(t, ctx, l.MaxSubscriptionsLimiter.Limit, c.MaxSubscriptions)
	assert.Equal(t, c.MaxLogLenBytes, l.MaxLogLenBytes)
}

func TestModuleLimitersPendingCallsAndClose(t *testing.T) {
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Owner: "owner", Workflow: "workflow"})
	for _, used := range []bool{false, true} {
		t.Run(fmt.Sprintf("used=%t", used), func(t *testing.T) {
			l := newModuleConfig(wasmlimits.Config{PendingCalls: 7})
			if used {
				require.NoError(t, l.PendingCallsLimiter.Use(ctx, 7))
				require.ErrorContains(t, l.PendingCallsLimiter.Use(ctx, 1), "resource limited for workflow[workflow]")
				require.NoError(t, l.PendingCallsLimiter.Free(ctx, 7))
				free, err := l.PendingCallsLimiter.Wait(ctx, 1)
				require.NoError(t, err)
				free()
			}
			done := make(chan error, 1)
			go func() { done <- closeModuleLimiters(l) }()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("limiter Close blocked")
			}
		})
	}
}
