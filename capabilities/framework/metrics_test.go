package framework

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestAllowedAttribute(t *testing.T) {
	allowed := []string{
		"component", "enclave.id", "endpoint", "outcome", "status_code",
		"capability_id", "method", "step_ref", "success", "error_type",
		"num_signatures", "num_ciphertexts", "num_requests",
		"max_concurrent", "metric_type",
		"workflow.id", "workflow.name", "workflow.owner", "org.id",
	}
	for _, k := range allowed {
		assert.True(t, allowedAttribute(k), "expected %q to be allowed", k)
	}

	// High-cardinality / author-controlled / free-text keys must be dropped.
	dropped := []string{
		"request_id", "message", "error", "name", "value",
		"execution_id", "label.foo", "label.tx_hash",
		"output_bytes",
		// Collides with Beholder's node_id resource attribute (INCIDENT-2677).
		"node.id", "node_id",
	}
	for _, k := range dropped {
		assert.False(t, allowedAttribute(k), "expected %q to be dropped", k)
	}
}

func TestDroppedMetricEvents(t *testing.T) {
	// request_id's only payload is the per-request ID; it must never become a metric.
	assert.Contains(t, droppedMetricEvents, "request_id")
}

func TestDurationHistogramBuckets(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	m := &MetricsEmitter{
		baseName:   "confidential-http@1.0.0-alpha",
		meter:      provider.Meter("test"),
		counters:   make(map[string]metric.Int64Counter),
		histograms: make(map[string]metric.Float64Histogram),
		lggr:       logger.Test(t),
	}
	// The enclave rounds sub-5ms durations to 0.
	m.Emit("signature_verification_completed", map[string]any{"duration_seconds": 0.0})
	m.Emit("app_execution_completed", map[string]any{"duration_seconds": 42.0})

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	histograms := map[string]metricdata.HistogramDataPoint[float64]{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			h, ok := md.Data.(metricdata.Histogram[float64])
			if !ok {
				continue
			}
			require.Len(t, h.DataPoints, 1, md.Name)
			histograms[md.Name] = h.DataPoints[0]
		}
	}
	require.Len(t, histograms, 2)

	sigVerify := histograms["confidential-http_1.0.0-alpha.signature_verification_completed.duration"]
	assert.Equal(t, durationBucketBoundaries, sigVerify.Bounds)
	assert.Equal(t, uint64(1), sigVerify.BucketCounts[0], "zero duration lands in the first bucket")

	appExec := histograms["confidential-http_1.0.0-alpha.app_execution_completed.duration"]
	assert.Equal(t, durationBucketBoundaries, appExec.Bounds)
	// 42s falls in (30, 45].
	assert.Equal(t, uint64(1), appExec.BucketCounts[slices.Index(durationBucketBoundaries, 45.0)])
}
