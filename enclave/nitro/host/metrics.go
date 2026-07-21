package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	executionOutcomeSuccess = "success"
	executionOutcomeError   = "error"
)

type executionMetadata struct {
	appID       string
	workflowID  string
	requestKind string
}

type executionMetrics interface {
	startExecution(executionMetadata) func(outcome string)
}

type noopExecutionMetrics struct{}

func (noopExecutionMetrics) startExecution(executionMetadata) func(string) {
	return func(string) {}
}

type hostMetrics struct {
	executionDuration  metric.Float64Histogram
	executionsInflight metric.Int64Gauge
	workflowActive     metric.Int64ObservableGauge

	mu           sync.Mutex
	inflight     int64
	workflowRefs map[string]int64
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

	metrics.workflowActive = active
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
