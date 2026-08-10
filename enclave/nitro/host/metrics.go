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
	enclaveMemoryPollInterval     = 30 * time.Second
	enclaveMemoryPollTimeout      = 30 * time.Second
	maxEnclaveMemoryResponseBytes = 64 * 1024
)

type executionMetrics interface {
	startExecution(executionMetadata) func(outcome string)
}

type noopExecutionMetrics struct{}

func (noopExecutionMetrics) startExecution(executionMetadata) func(string) {
	return func(string) {}
}

type enclaveMemorySnapshot struct {
	goRuntimeBytes  int64
	processRSSBytes int64
}

type hostMetrics struct {
	executionDuration  metric.Float64Histogram
	executionsInflight metric.Int64Gauge
	workflowActive     metric.Int64ObservableGauge
	goRuntimeMemory    metric.Int64ObservableGauge
	processRSSMemory   metric.Int64ObservableGauge

	mu           sync.Mutex
	inflight     int64
	workflowRefs map[string]int64
	memory       atomic.Pointer[enclaveMemorySnapshot]
}

func newHostMetrics(meter metric.Meter) (*hostMetrics, error) {
	duration, err := meter.Float64Histogram(
		"confidential_compute.enclave.execution.duration",
		metric.WithDescription("Wall-clock duration of one post-quorum enclave execution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
			2.5, 5, 10, 30, 60, 120, 300, 600,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave execution duration histogram: %w", err)
	}
	inflight, err := meter.Int64Gauge(
		"confidential_compute.enclave.executions.inflight",
		metric.WithDescription("Actual enclave executions currently in flight in this host"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave executions in-flight gauge: %w", err)
	}
	metrics := &hostMetrics{
		executionDuration:  duration,
		executionsInflight: inflight,
		workflowRefs:       make(map[string]int64),
	}
	// Observable state prevents the cumulative SDK from retaining every historical workflow ID.
	active, err := meter.Int64ObservableGauge(
		"confidential_compute.enclave.workflow.active",
		metric.WithDescription("Whether a workflow has an enclave execution in flight in this host"),
		metric.WithUnit("1"),
		metric.WithInt64Callback(metrics.observeActiveWorkflows),
	)
	if err != nil {
		return nil, fmt.Errorf("create active workflow gauge: %w", err)
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
	metrics.goRuntimeMemory = goRuntimeMemory
	metrics.processRSSMemory = processRSSMemory
	metrics.executionsInflight.Record(context.Background(), 0)
	return metrics, nil
}

func (m *hostMetrics) observeActiveWorkflows(ctx context.Context, observer metric.Int64Observer) error {
	m.mu.Lock()
	workflowIDs := make([]string, 0, len(m.workflowRefs))
	for workflowID := range m.workflowRefs {
		workflowIDs = append(workflowIDs, workflowID)
	}
	m.mu.Unlock()

	for _, workflowID := range workflowIDs {
		observer.Observe(
			1,
			metric.WithAttributes(attribute.String("workflow.id", workflowID)),
		)
	}
	return nil
}

// Memory is sampled over vsock in a background goroutine. These callbacks only
// load the latest immutable snapshot, so metric collection never waits on the enclave.
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

func (m *hostMetrics) startExecution(metadata executionMetadata) func(string) {
	ctx := context.Background()

	m.mu.Lock()
	m.inflight++
	m.executionsInflight.Record(ctx, m.inflight)
	if metadata.workflowID != "" {
		m.workflowRefs[metadata.workflowID]++
	}
	m.mu.Unlock()

	startedAt := time.Now()
	var once sync.Once
	return func(outcome string) {
		once.Do(func() {
			if outcome != executionOutcomeSuccess {
				outcome = executionOutcomeError
			}

			attrs := []attribute.KeyValue{
				attribute.String("app.id", metadata.appID),
				attribute.String("outcome", outcome),
			}
			if metadata.requestKind != "" {
				attrs = append(attrs, attribute.String("request.kind", metadata.requestKind))
			}
			m.executionDuration.Record(
				ctx,
				time.Since(startedAt).Seconds(),
				metric.WithAttributes(attrs...),
			)

			m.mu.Lock()
			m.inflight--
			m.executionsInflight.Record(ctx, m.inflight)
			if metadata.workflowID != "" {
				m.workflowRefs[metadata.workflowID]--
				if m.workflowRefs[metadata.workflowID] == 0 {
					delete(m.workflowRefs, metadata.workflowID)
				}
			}
			m.mu.Unlock()
		})
	}
}
