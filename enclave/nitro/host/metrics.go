package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	executionOutcomeSuccess       = "success"
	executionOutcomeError         = "error"
	executionFailureCapacity      = "capacity"
	executionFailureConflict      = "conflict"
	executionFailureInternal      = "internal"
	executionFailureInvalid       = "invalid_request"
	executionFailureProtocol      = "protocol"
	executionFailureTimeout       = "timeout"
	executionFailureTransport     = "transport"
	executionFailureUnknown       = "unknown"
	enclaveMemoryPollInterval     = 30 * time.Second
	enclaveMemoryPollTimeout      = 30 * time.Second
	maxEnclaveMemoryResponseBytes = 64 * 1024
)

var executionDurationBuckets = []float64{
	0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
	2.5, 5, 10, 30, 60, 120, 300, 600,
}

type executionMetrics interface {
	startExecution(executionMetadata, time.Duration) func(outcome, failureReason string)
}

type noopExecutionMetrics struct{}

func (noopExecutionMetrics) startExecution(executionMetadata, time.Duration) func(string, string) {
	return func(string, string) {}
}

type enclaveMemorySnapshot struct {
	totalBytes      int64
	goRuntimeBytes  int64
	processRSSBytes int64
}

type hostMetrics struct {
	// Post-quorum enclave execution time for one batch.
	executionDuration metric.Float64Histogram
	// End-to-end host HTTP handler time for one request.
	endpointDuration metric.Float64Histogram
	// Time from the first matching request until quorum dispatch for one batch.
	quorumWaitDuration metric.Float64Histogram
	// Quorum wait plus post-quorum enclave execution time for one batch.
	totalDuration         metric.Float64Histogram
	executionsStarted     metric.Int64Counter
	executionsRejected    metric.Int64Counter
	executionsInflight    metric.Int64ObservableGauge
	executionsInflightMax metric.Int64ObservableGauge
	workflowActive        metric.Int64ObservableGauge
	workflowsActiveMax    metric.Int64ObservableGauge
	totalMemory           metric.Int64ObservableGauge
	goRuntimeMemory       metric.Int64ObservableGauge
	processRSSMemory      metric.Int64ObservableGauge

	now              func() time.Time
	mu               sync.Mutex
	inflight         int64
	inflightMax      int64
	workflowCountMax int64
	workflowRefs     map[string]int64
	memory           atomic.Pointer[enclaveMemorySnapshot]
}

func newHostMetrics(meter metric.Meter) (*hostMetrics, error) {
	return newHostMetricsWithClock(meter, time.Now)
}

func newHostMetricsWithClock(meter metric.Meter, now func() time.Time) (*hostMetrics, error) {
	duration, err := meter.Float64Histogram(
		"confidential_compute.enclave.execution.duration",
		metric.WithDescription("Wall-clock duration of one post-quorum enclave execution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(executionDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave execution duration histogram: %w", err)
	}
	endpointDuration, err := meter.Float64Histogram(
		"confidential_compute.enclave.host.endpoint.duration",
		metric.WithDescription("End-to-end wall-clock duration of an enclave host HTTP request"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(executionDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave host endpoint duration histogram: %w", err)
	}
	quorumWait, err := meter.Float64Histogram(
		"confidential_compute.enclave.execution.quorum_wait.duration",
		metric.WithDescription("Wall-clock duration from the first matching host request until quorum dispatch"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(executionDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave quorum wait duration histogram: %w", err)
	}
	total, err := meter.Float64Histogram(
		"confidential_compute.enclave.execution.total.duration",
		metric.WithDescription("Wall-clock duration from the first matching host request through enclave execution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(executionDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave total execution duration histogram: %w", err)
	}
	started, err := meter.Int64Counter(
		"confidential_compute.enclave.executions.started",
		metric.WithDescription("Enclave executions dispatched after reaching quorum"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave executions started counter: %w", err)
	}
	rejected, err := meter.Int64Counter(
		"confidential_compute.enclave.executions.rejected",
		metric.WithDescription("Enclave executions rejected after dispatch"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave executions rejected counter: %w", err)
	}
	inflight, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.executions.inflight",
		metric.WithDescription("Actual enclave executions currently in flight in this host"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave executions in-flight gauge: %w", err)
	}
	inflightMax, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.executions.inflight.max",
		metric.WithDescription("Maximum enclave executions in flight since the previous metric collection"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create maximum enclave executions in-flight gauge: %w", err)
	}
	metrics := &hostMetrics{
		executionDuration:     duration,
		endpointDuration:      endpointDuration,
		quorumWaitDuration:    quorumWait,
		totalDuration:         total,
		executionsStarted:     started,
		executionsRejected:    rejected,
		executionsInflight:    inflight,
		executionsInflightMax: inflightMax,
		now:                   now,
		workflowRefs:          make(map[string]int64),
	}
	active, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.workflow.active",
		metric.WithDescription("Whether a workflow has an enclave execution in flight in this host"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create active workflow gauge: %w", err)
	}
	activeMax, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.workflows.active.max",
		metric.WithDescription("Maximum distinct workflows executing since the previous metric collection"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create maximum active workflows gauge: %w", err)
	}
	goRuntimeMemory, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.memory.go_runtime",
		metric.WithDescription("Memory mapped by the enclave Go runtime, quantized to the nearest MiB inside the enclave"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(metrics.observeGoRuntimeMemory),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave Go runtime memory gauge: %w", err)
	}
	totalMemory, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.memory.total",
		metric.WithDescription("Total RAM of the enclave guest (/proc/meminfo MemTotal), quantized to the nearest MiB inside the enclave; the denominator for memory-pressure ratios"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(metrics.observeTotalMemory),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave total memory gauge: %w", err)
	}
	processRSSMemory, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.memory.rss",
		metric.WithDescription("Resident memory of the enclave process, including native Wasmtime allocations, quantized to the nearest MiB inside the enclave"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(metrics.observeProcessRSSMemory),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave process RSS memory gauge: %w", err)
	}

	metrics.workflowActive = active
	metrics.workflowsActiveMax = activeMax
	metrics.totalMemory = totalMemory
	metrics.goRuntimeMemory = goRuntimeMemory
	metrics.processRSSMemory = processRSSMemory
	_, err = meter.RegisterCallback(
		metrics.observeExecutionLoad,
		metrics.executionsInflight,
		metrics.executionsInflightMax,
		metrics.workflowActive,
		metrics.workflowsActiveMax,
	)
	if err != nil {
		return nil, fmt.Errorf("register enclave execution load callback: %w", err)
	}
	return metrics, nil
}

func (m *hostMetrics) recordEndpointDuration(ctx context.Context, endpoint string, duration time.Duration) {
	m.endpointDuration.Record(
		ctx,
		duration.Seconds(),
		metric.WithAttributes(attribute.String("endpoint", endpoint)),
	)
}

func (m *hostMetrics) observeExecutionLoad(_ context.Context, observer metric.Observer) error {
	m.mu.Lock()
	inflight := m.inflight
	inflightMax := m.inflightMax
	workflowsActiveMax := m.workflowCountMax
	workflowIDs := make([]string, 0, len(m.workflowRefs))
	for workflowID := range m.workflowRefs {
		workflowIDs = append(workflowIDs, workflowID)
	}
	// Peaks cover work that starts and finishes between exports. Resetting to the
	// current load preserves the maximum correctly across collection windows.
	m.inflightMax = inflight
	m.workflowCountMax = int64(len(m.workflowRefs))
	m.mu.Unlock()

	observer.ObserveInt64(m.executionsInflight, inflight)
	observer.ObserveInt64(m.executionsInflightMax, inflightMax)
	observer.ObserveInt64(m.workflowsActiveMax, workflowsActiveMax)
	for _, workflowID := range workflowIDs {
		observer.ObserveInt64(
			m.workflowActive,
			1,
			metric.WithAttributes(attribute.String("workflow.id", workflowID)),
		)
	}
	return nil
}

// Memory is sampled over vsock in a background goroutine. These callbacks only
// load the latest immutable snapshot, so metric collection never waits on the enclave.
// observeTotalMemory skips zero values so hosts polling an enclave that
// predates the totalMB field export no series instead of a bogus zero.
func (m *hostMetrics) observeTotalMemory(_ context.Context, observer metric.Int64Observer) error {
	snapshot := m.memory.Load()
	if snapshot != nil && snapshot.totalBytes > 0 {
		observer.Observe(snapshot.totalBytes)
	}
	return nil
}

func (m *hostMetrics) observeGoRuntimeMemory(_ context.Context, observer metric.Int64Observer) error {
	snapshot := m.memory.Load()
	if snapshot != nil && snapshot.goRuntimeBytes > 0 {
		observer.Observe(snapshot.goRuntimeBytes)
	}
	return nil
}

func (m *hostMetrics) observeProcessRSSMemory(_ context.Context, observer metric.Int64Observer) error {
	snapshot := m.memory.Load()
	if snapshot != nil && snapshot.processRSSBytes > 0 {
		observer.Observe(snapshot.processRSSBytes)
	}
	return nil
}

func (m *hostMetrics) recordEnclaveMemory(estimate types.MemoryEstimateResponse) {
	m.memory.Store(&enclaveMemorySnapshot{
		totalBytes:      mibToBytes(estimate.TotalMB),
		goRuntimeBytes:  mibToBytes(estimate.UsedMB),
		processRSSBytes: mibToBytes(estimate.RSSMB),
	})
}

func (m *hostMetrics) clearEnclaveMemory() {
	m.memory.Store(nil)
}

// monitorEnclaveMemory keeps network I/O outside OTel callbacks and clears a
// cached sample after an error so an unreachable enclave cannot look healthy.
func (m *hostMetrics) monitorEnclaveMemory(
	ctx context.Context,
	client *http.Client,
	lggr cllogger.SugaredLogger,
	interval time.Duration,
	timeout time.Duration,
) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			requestCtx, cancel := context.WithTimeout(ctx, timeout)
			err := m.collectEnclaveMemory(requestCtx, client)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				m.clearEnclaveMemory()
				lggr.Warnw("failed to collect enclave memory metrics",
					"event", "ENCLAVE_MEMORY_METRICS_ERR",
					"error", err)
			}
			timer.Reset(interval)
		}
	}
}

func (m *hostMetrics) collectEnclaveMemory(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vsockPrefix+types.MemoryPath, nil)
	if err != nil {
		return fmt.Errorf("create enclave memory request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request enclave memory: %w", err)
	}
	defer util.SafeClose(resp)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnclaveMemoryResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read enclave memory response: %w", err)
	}
	if len(body) > maxEnclaveMemoryResponseBytes {
		return fmt.Errorf("enclave memory response exceeds %d bytes", maxEnclaveMemoryResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enclave memory endpoint returned status %d", resp.StatusCode)
	}

	var estimate types.MemoryEstimateResponse
	if err := json.Unmarshal(body, &estimate); err != nil {
		return fmt.Errorf("decode enclave memory response: %w", err)
	}
	m.recordEnclaveMemory(estimate)
	return nil
}

// MemoryEstimateResponse contains integer MiB values deliberately quantized
// inside the enclave. This changes only the OTel unit; it does not add precision.
func mibToBytes(value uint64) int64 {
	const bytesPerMiB = uint64(1024 * 1024)
	if value > uint64(math.MaxInt64)/bytesPerMiB {
		return math.MaxInt64
	}
	return int64(value * bytesPerMiB)
}

func (m *hostMetrics) startExecution(metadata executionMetadata, quorumWait time.Duration) func(string, string) {
	ctx := context.Background()
	baseAttrs := executionMetricAttributes(metadata)
	m.executionsStarted.Add(ctx, 1, metric.WithAttributes(baseAttrs...))
	m.quorumWaitDuration.Record(ctx, quorumWait.Seconds(), metric.WithAttributes(baseAttrs...))

	m.mu.Lock()
	startedAt := m.now()
	m.inflight++
	if m.inflight > m.inflightMax {
		m.inflightMax = m.inflight
	}
	if metadata.workflowID != "" {
		m.workflowRefs[metadata.workflowID]++
		if active := int64(len(m.workflowRefs)); active > m.workflowCountMax {
			m.workflowCountMax = active
		}
	}
	m.mu.Unlock()

	var once sync.Once
	return func(outcome, failureReason string) {
		once.Do(func() {
			if outcome != executionOutcomeSuccess {
				outcome = executionOutcomeError
				if failureReason == "" {
					failureReason = executionFailureUnknown
				}
			} else {
				failureReason = ""
			}

			m.mu.Lock()
			finishedAt := m.now()
			m.inflight--
			if metadata.workflowID != "" {
				m.workflowRefs[metadata.workflowID]--
				if m.workflowRefs[metadata.workflowID] == 0 {
					delete(m.workflowRefs, metadata.workflowID)
				}
			}
			m.mu.Unlock()

			duration := finishedAt.Sub(startedAt)
			if duration < 0 {
				duration = 0
			}
			attrs := executionResultAttributes(metadata, outcome, failureReason)
			options := metric.WithAttributes(attrs...)
			m.executionDuration.Record(ctx, duration.Seconds(), options)
			m.totalDuration.Record(ctx, (quorumWait + duration).Seconds(), options)
			if failureReason == executionFailureCapacity {
				m.executionsRejected.Add(ctx, 1, metric.WithAttributes(baseAttrs...))
			}
		})
	}
}

func executionMetricAttributes(metadata executionMetadata) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("app.id", metadata.appID)}
	if metadata.requestKind != "" {
		attrs = append(attrs, attribute.String("request.kind", metadata.requestKind))
	}
	return attrs
}

func executionResultAttributes(metadata executionMetadata, outcome, failureReason string) []attribute.KeyValue {
	attrs := executionMetricAttributes(metadata)
	attrs = append(attrs, attribute.String("outcome", outcome))
	if failureReason != "" {
		attrs = append(attrs, attribute.String("failure.reason", failureReason))
	}
	return attrs
}

func executionFailureReasonForStatus(status int) string {
	switch status {
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return executionFailureTimeout
	case http.StatusConflict:
		return executionFailureConflict
	case http.StatusTooManyRequests:
		return executionFailureCapacity
	}
	if status >= 400 && status < 500 {
		return executionFailureInvalid
	}
	if status >= 500 && status < 600 {
		return executionFailureInternal
	}
	return executionFailureUnknown
}
