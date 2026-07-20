package main

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	executionDurationMetric  = "confidential_compute.enclave.execution.duration"
	executionsInflightMetric = "confidential_compute.enclave.executions.inflight"
	workflowActiveMetric     = "confidential_compute.enclave.workflow.active"
)

func newTestHostMetrics(t *testing.T) (*hostMetrics, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
	})
	metrics, err := newHostMetrics(provider.Meter(hostInstrumentationScope))
	require.NoError(t, err)
	return metrics, reader
}

func collectHostMetrics(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var data metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &data))
	return data
}

func findMetric(data metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
	for _, scope := range data.ScopeMetrics {
		for _, candidate := range scope.Metrics {
			if candidate.Name == name {
				return candidate, true
			}
		}
	}
	return metricdata.Metrics{}, false
}

func requireMetric(t *testing.T, data metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()
	result, ok := findMetric(data, name)
	require.True(t, ok, "metric %s was not collected", name)
	return result
}

func gaugeValue(t *testing.T, data metricdata.ResourceMetrics, name string, attrs map[string]string) int64 {
	t.Helper()
	gauge, ok := requireMetric(t, data, name).Data.(metricdata.Gauge[int64])
	require.True(t, ok, "metric %s was not an int64 gauge", name)
	for _, point := range gauge.DataPoints {
		if dataPointHasAttributes(point.Attributes, attrs) {
			return point.Value
		}
	}
	t.Fatalf("metric %s had no data point with attributes %v", name, attrs)
	return 0
}

func dataPointHasAttributes(set attribute.Set, attrs map[string]string) bool {
	if set.Len() != len(attrs) {
		return false
	}
	for key, expected := range attrs {
		value, ok := set.Value(attribute.Key(key))
		if !ok || value.AsString() != expected {
			return false
		}
	}
	return true
}

func durationHistogram(t *testing.T, data metricdata.ResourceMetrics) metricdata.Histogram[float64] {
	t.Helper()
	histogram, ok := requireMetric(t, data, executionDurationMetric).Data.(metricdata.Histogram[float64])
	require.True(t, ok, "metric %s was not a float64 histogram", executionDurationMetric)
	return histogram
}

func histogramCount(t *testing.T, histogram metricdata.Histogram[float64], attrs map[string]string) uint64 {
	t.Helper()
	for _, point := range histogram.DataPoints {
		if dataPointHasAttributes(point.Attributes, attrs) {
			return point.Count
		}
	}
	t.Fatalf("duration histogram had no data point with attributes %v", attrs)
	return 0
}

func TestHostMetricsExecutionLifecycle(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	metadata := executionMetadata{
		appID:       "confidential-workflows",
		workflowID:  "workflow-a",
		requestKind: "trigger",
	}

	finish := metrics.startExecution(metadata)
	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(1), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))

	finish(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, uint64(1), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":       "confidential-workflows",
		"outcome":      executionOutcomeSuccess,
		"request.kind": "trigger",
	}))
}

func TestHostMetricsExecutionError(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	finish := metrics.startExecution(executionMetadata{
		appID:       "confidential-workflows",
		workflowID:  "workflow-a",
		requestKind: "subscribe",
	})

	finish(executionOutcomeError)
	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, uint64(1), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":       "confidential-workflows",
		"outcome":      executionOutcomeError,
		"request.kind": "subscribe",
	}))
}

func TestHostMetricsConcurrentSameWorkflow(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	metadata := executionMetadata{appID: "confidential-workflows", workflowID: "workflow-a", requestKind: "trigger"}

	finishFirst := metrics.startExecution(metadata)
	finishSecond := metrics.startExecution(metadata)
	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(2), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))

	finishFirst(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(1), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))

	finishSecond(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, uint64(2), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":       "confidential-workflows",
		"outcome":      executionOutcomeSuccess,
		"request.kind": "trigger",
	}))
}

func TestHostMetricsConcurrentDifferentWorkflows(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	finishFirst := metrics.startExecution(executionMetadata{appID: "confidential-workflows", workflowID: "workflow-a"})
	finishSecond := metrics.startExecution(executionMetadata{appID: "confidential-workflows", workflowID: "workflow-b"})

	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(2), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-b"}))

	finishFirst(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(1), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-b"}))

	finishSecond(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-b"}))
}

func TestHostMetricsUnknownWorkflow(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	finish := metrics.startExecution(executionMetadata{appID: "confidential-http"})
	finish(executionOutcomeSuccess)

	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	_, found := findMetric(data, workflowActiveMetric)
	assert.False(t, found)
	assert.Equal(t, uint64(1), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":  "confidential-http",
		"outcome": executionOutcomeSuccess,
	}))
}

func TestHostMetricsFinishIsIdempotent(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	finish := metrics.startExecution(executionMetadata{appID: "confidential-workflows", workflowID: "workflow-a"})

	finish(executionOutcomeSuccess)
	finish(executionOutcomeError)

	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, uint64(1), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":  "confidential-workflows",
		"outcome": executionOutcomeSuccess,
	}))
}

func TestHostMetricsHistogramBoundaries(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	finish := metrics.startExecution(executionMetadata{appID: "confidential-workflows"})
	finish(executionOutcomeSuccess)

	histogram := durationHistogram(t, collectHostMetrics(t, reader))
	require.Len(t, histogram.DataPoints, 1)
	assert.Equal(t, []float64{
		0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
		2.5, 5, 10, 30, 60, 120, 300, 600,
	}, histogram.DataPoints[0].Bounds)
}

func TestHostMetricsConcurrentUpdates(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	const executions = 100

	var wg sync.WaitGroup
	for range executions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			finish := metrics.startExecution(executionMetadata{
				appID:      "confidential-workflows",
				workflowID: "workflow-a",
			})
			finish(executionOutcomeSuccess)
		}()
	}
	wg.Wait()

	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assert.Equal(t, int64(0), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"}))
	assert.Equal(t, uint64(executions), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":  "confidential-workflows",
		"outcome": executionOutcomeSuccess,
	}))
	assert.Empty(t, metrics.workflowRefs)
}
