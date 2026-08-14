package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap/zapcore"
)

const (
	executionDurationMetric  = "confidential_compute.enclave.execution.duration"
	endpointDurationMetric   = "confidential_compute.enclave.host.endpoint.duration"
	executionsInflightMetric = "confidential_compute.enclave.executions.inflight"
	workflowActiveMetric     = "confidential_compute.enclave.workflow.active"
	goRuntimeMemoryMetric    = "confidential_compute.enclave.memory.go_runtime"
	processRSSMemoryMetric   = "confidential_compute.enclave.memory.rss"
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

func assertNoGaugePoint(t *testing.T, data metricdata.ResourceMetrics, name string, attrs map[string]string) {
	t.Helper()
	result, found := findMetric(data, name)
	if !found {
		return
	}
	gauge, ok := result.Data.(metricdata.Gauge[int64])
	require.True(t, ok, "metric %s was not an int64 gauge", name)
	for _, point := range gauge.DataPoints {
		assert.False(t, dataPointHasAttributes(point.Attributes, attrs), "metric %s retained attributes %v", name, attrs)
	}
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

func TestHostMetricsEndpointLatency(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	handler := instrumentEndpointLatency(metrics, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PublicKeyPath:
			_, _ = w.Write([]byte("ok"))
		case types.ExecutePath:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))

	for _, path := range []string{types.PublicKeyPath, types.ExecutePath, "/client-supplied-path"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	metricData := requireMetric(t, collectHostMetrics(t, reader), endpointDurationMetric)
	histogram, ok := metricData.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	assert.Equal(t, "s", metricData.Unit)
	assert.Equal(t, uint64(1), histogramCount(t, histogram, map[string]string{"endpoint": types.PublicKeyPath}))
	assert.Equal(t, uint64(1), histogramCount(t, histogram, map[string]string{"endpoint": types.ExecutePath}))
	assert.Equal(t, uint64(1), histogramCount(t, histogram, map[string]string{"endpoint": "unmatched"}))
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
	assert.Equal(t, int64(1), gaugeValue(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-b"}))

	finishSecond(executionOutcomeSuccess)
	data = collectHostMetrics(t, reader)
	assert.Equal(t, int64(0), gaugeValue(t, data, executionsInflightMetric, nil))
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-b"})
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
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
	assertNoGaugePoint(t, data, workflowActiveMetric, map[string]string{"workflow.id": "workflow-a"})
	assert.Equal(t, uint64(executions), histogramCount(t, durationHistogram(t, data), map[string]string{
		"app.id":  "confidential-workflows",
		"outcome": executionOutcomeSuccess,
	}))
	assert.Empty(t, metrics.workflowRefs)
}

func TestHostMetricsDoesNotRetainCompletedWorkflows(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	const workflows = 1_000

	for i := range workflows {
		finish := metrics.startExecution(executionMetadata{
			appID:      "confidential-workflows",
			workflowID: fmt.Sprintf("workflow-%d", i),
		})
		finish(executionOutcomeSuccess)
	}

	data := collectHostMetrics(t, reader)
	_, found := findMetric(data, workflowActiveMetric)
	assert.False(t, found)
	assert.Empty(t, metrics.workflowRefs)
}

func TestHostMetricsEnclaveMemory(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)

	metrics.recordEnclaveMemory(types.MemoryEstimateResponse{UsedMB: 32, RSSMB: 96})
	data := collectHostMetrics(t, reader)
	goRuntimeMetric := requireMetric(t, data, goRuntimeMemoryMetric)
	processRSSMetric := requireMetric(t, data, processRSSMemoryMetric)
	assert.Equal(t, int64(32*1024*1024), gaugeValue(t, data, goRuntimeMemoryMetric, nil))
	assert.Equal(t, int64(96*1024*1024), gaugeValue(t, data, processRSSMemoryMetric, nil))
	assert.Equal(t, "By", goRuntimeMetric.Unit)
	assert.Equal(t, "By", processRSSMetric.Unit)
	assert.Contains(t, goRuntimeMetric.Description, "quantized to the nearest MiB inside the enclave")
	assert.Contains(t, processRSSMetric.Description, "quantized to the nearest MiB inside the enclave")

	metrics.clearEnclaveMemory()
	data = collectHostMetrics(t, reader)
	_, found := findMetric(data, goRuntimeMemoryMetric)
	assert.False(t, found)
	_, found = findMetric(data, processRSSMemoryMetric)
	assert.False(t, found)
}

func TestHostMetricsOmitsUnavailableMemoryValues(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)

	metrics.recordEnclaveMemory(types.MemoryEstimateResponse{UsedMB: 32})
	data := collectHostMetrics(t, reader)
	assert.Equal(t, int64(32*1024*1024), gaugeValue(t, data, goRuntimeMemoryMetric, nil))
	_, found := findMetric(data, processRSSMemoryMetric)
	assert.False(t, found)
}

type memoryRoundTripResult struct {
	status int
	body   string
	err    error
}

type memorySequenceTransport struct {
	results chan memoryRoundTripResult
}

func (t *memorySequenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case result := <-t.results:
		if result.err != nil {
			return nil, result.err
		}
		return &http.Response{
			StatusCode: result.status,
			Body:       io.NopCloser(strings.NewReader(result.body)),
			Header:     make(http.Header),
		}, nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func TestCollectEnclaveMemory(t *testing.T) {
	transport := &mockRoundTripper{response: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"usedMB":32,"rssMB":96}`)),
		Header:     make(http.Header),
	}}
	metrics := &hostMetrics{}

	require.NoError(t, metrics.collectEnclaveMemory(context.Background(), &http.Client{Transport: transport}))

	require.Len(t, transport.requests, 1)
	assert.Equal(t, http.MethodGet, transport.requests[0].Method)
	assert.Equal(t, types.MemoryPath, transport.requests[0].URL.Path)
	snapshot := metrics.memory.Load()
	require.NotNil(t, snapshot)
	assert.Equal(t, int64(32*1024*1024), snapshot.goRuntimeBytes)
	assert.Equal(t, int64(96*1024*1024), snapshot.processRSSBytes)
}

func TestCollectEnclaveMemoryRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		want     string
	}{
		{
			name: "non-OK status",
			response: &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader("not ready")),
			},
			want: "status 503",
		},
		{
			name: "malformed JSON",
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"usedMB":`)),
			},
			want: "decode enclave memory response",
		},
		{
			name: "oversized body",
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(make([]byte, maxEnclaveMemoryResponseBytes+1))),
			},
			want: "response exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metrics := &hostMetrics{}
			client := &http.Client{Transport: &mockRoundTripper{response: test.response}}

			err := metrics.collectEnclaveMemory(context.Background(), client)
			require.ErrorContains(t, err, test.want)
			assert.Nil(t, metrics.memory.Load())
		})
	}
}

func TestMonitorEnclaveMemoryClearsFailedSampleAndStops(t *testing.T) {
	transport := &memorySequenceTransport{results: make(chan memoryRoundTripResult, 2)}
	transport.results <- memoryRoundTripResult{
		status: http.StatusOK,
		body:   `{"usedMB":32,"rssMB":96}`,
	}

	metrics := &hostMetrics{}
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		metrics.monitorEnclaveMemory(ctx, &http.Client{Transport: transport}, lggr, time.Millisecond, time.Second)
		close(done)
	}()

	require.Eventually(t, func() bool {
		snapshot := metrics.memory.Load()
		return snapshot != nil && snapshot.goRuntimeBytes == 32*1024*1024 && snapshot.processRSSBytes == 96*1024*1024
	}, 2*time.Second, time.Millisecond)

	transport.results <- memoryRoundTripResult{err: errors.New("vsock unavailable")}
	require.Eventually(t, func() bool {
		for _, entry := range logs.All() {
			if entry.ContextMap()["event"] == "ENCLAVE_MEMORY_METRICS_ERR" {
				return true
			}
		}
		return false
	}, 2*time.Second, time.Millisecond)

	cancel()
	waitForTestSignal(t, done, "memory monitor shutdown")
	assert.Nil(t, metrics.memory.Load())
	observedFieldsByEvent(t, logs, "ENCLAVE_MEMORY_METRICS_ERR")
}
