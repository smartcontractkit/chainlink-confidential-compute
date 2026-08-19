package framework

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// MetricsEmitter implements types.Emitter and emits metrics via OTel.
// It converts Emit calls into OTel counters and histograms.
type MetricsEmitter struct {
	baseName   string
	meter      metric.Meter
	counters   map[string]metric.Int64Counter
	histograms map[string]metric.Float64Histogram
	mux        sync.RWMutex
	lggr       logger.Logger
}

var _ types.Emitter = (*MetricsEmitter)(nil)

func NewMetricsEmitter(name string, lggr logger.Logger) *MetricsEmitter {
	m := &MetricsEmitter{
		baseName:   name,
		meter:      beholder.GetMeter(),
		counters:   make(map[string]metric.Int64Counter),
		histograms: make(map[string]metric.Float64Histogram),
		lggr:       lggr,
	}
	return m
}

// allowedMetricAttributes is the set of detail keys promoted to OTel attributes.
// Only low-cardinality keys (bounded enums, small ints, categorical flags, fixed
// host tags) are allowed; everything else is dropped to prevent Prometheus series
// explosion from per-request or workflow-author-controlled values (request_id,
// message, free-text error strings, workflow_id/execution_id, user_metric name/
// value/labels). ScopedEmitter defaults ("component", "enclave.id") merge into
// details before Emit, so they must be allowed here to keep enclave tagging.
var allowedMetricAttributes = map[string]struct{}{
	"component":       {},
	"enclave.id":      {},
	"endpoint":        {},
	"outcome":         {},
	"status_code":     {},
	"capability_id":   {},
	"method":          {},
	"step_ref":        {},
	"success":         {},
	"error_type":      {},
	"num_signatures":  {},
	"num_ciphertexts": {},
	"num_requests":    {},
	"max_concurrent":  {},
	"metric_type":     {},
	"workflow_id":     {},
}

// allowedAttribute returns true if k is a low-cardinality key that may become an
// OTel attribute. Extracted from Emit so the filter is unit-testable without an
// OTel meter.
func allowedAttribute(k string) bool {
	_, ok := allowedMetricAttributes[k]
	return ok
}

// droppedMetricEvents are events whose entire payload is high-cardinality and
// therefore must never become an OTel metric. "request_id" carries only the
// per-request ID, which would mint one series per request.
var droppedMetricEvents = map[string]struct{}{
	"request_id": {},
}

// Emit implements types.Emitter. It converts the event and details into OTel metrics.
// - If details contains "duration_seconds" (float64), it records a histogram with that value.
// - Otherwise, it increments a counter by 1.
// - Events in droppedMetricEvents are skipped entirely.
// - Only allowlisted, low-cardinality detail keys become OTel attributes; all
//   other keys are dropped to bound the number of distinct time series.
func (m *MetricsEmitter) Emit(event string, details map[string]any) {
	if _, drop := droppedMetricEvents[event]; drop {
		return
	}
	ctx := context.Background()

	var attrs []attribute.KeyValue
	var durationSeconds float64
	var hasDuration bool

	for k, v := range details {
		if k == "duration_seconds" {
			if d, ok := v.(float64); ok {
				durationSeconds = d
				hasDuration = true
			}
			continue
		}
		if !allowedAttribute(k) {
			continue
		}
		switch val := v.(type) {
		case string:
			attrs = append(attrs, attribute.String(k, val))
		case float64:
			attrs = append(attrs, attribute.Float64(k, val))
		case int:
			attrs = append(attrs, attribute.Int(k, val))
		case int64:
			attrs = append(attrs, attribute.Int64(k, val))
		case bool:
			attrs = append(attrs, attribute.Bool(k, val))
		default:
			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", val)))
		}
	}

	// Increment the counter for this event
	m.getOrCreateCounterAndAdd(ctx, event, 1, attrs)

	// If there's a duration, also record it as a histogram
	if hasDuration {
		m.getOrCreateHistogramAndRecord(ctx, event+".duration", durationSeconds, attrs)
	}
}

// Allowed characters: [A-Za-z0-9_./-]
// The regex pattern below matches any character *not* in this set.
const illegalCharPattern = `[^A-Za-z0-9_./-]`

var illegalCharRegex = regexp.MustCompile(illegalCharPattern)

// sanitizeName finds all illegal characters in the string and replaces them
// with an underscore (_).
func sanitizeName(name string) string {
	// The core find-and-replace command
	return illegalCharRegex.ReplaceAllString(name, "_")
}

// getOrCreateCounterAndAdd is the internal helper that contains the core logic for
// safely accessing/creating the counter and adding the value with optional attributes.
func (m *MetricsEmitter) getOrCreateCounterAndAdd(ctx context.Context, name string, value int64, attrs []attribute.KeyValue) {
	key := sanitizeName(m.baseName + "." + name)

	m.mux.RLock()
	counter, exists := m.counters[key]
	m.mux.RUnlock()

	if exists {
		m.addValue(ctx, counter, value, attrs)
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	// Double-check in case another goroutine created it while we waited for the write lock
	if counter, exists := m.counters[key]; exists {
		m.addValue(ctx, counter, value, attrs)
		return
	}

	// Create new counter
	counter, err := m.meter.Int64Counter(key)
	if err != nil {
		m.lggr.Errorw("failed to create counter", "key", key, "error", err)
		return
	}

	m.counters[key] = counter
	m.addValue(ctx, counter, value, attrs)
}

func (m *MetricsEmitter) addValue(ctx context.Context, counter metric.Int64Counter, value int64, attrs []attribute.KeyValue) {
	if len(attrs) > 0 {
		counter.Add(ctx, value, metric.WithAttributes(attrs...))
	} else {
		counter.Add(ctx, value)
	}
}

func (m *MetricsEmitter) getOrCreateHistogramAndRecord(ctx context.Context, name string, value float64, attrs []attribute.KeyValue) {
	key := sanitizeName(m.baseName + "." + name)

	m.mux.RLock()
	histogram, exists := m.histograms[key]
	m.mux.RUnlock()

	if exists {
		m.recordHistogramValue(ctx, histogram, value, attrs)
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	// Double-check in case another goroutine created it while we waited for the write lock
	if histogram, exists := m.histograms[key]; exists {
		m.recordHistogramValue(ctx, histogram, value, attrs)
		return
	}

	// Create new histogram
	histogram, err := m.meter.Float64Histogram(key)
	if err != nil {
		m.lggr.Errorw("failed to create histogram", "key", key, "error", err)
		return
	}

	m.histograms[key] = histogram
	m.recordHistogramValue(ctx, histogram, value, attrs)
}

func (m *MetricsEmitter) recordHistogramValue(ctx context.Context, histogram metric.Float64Histogram, value float64, attrs []attribute.KeyValue) {
	if len(attrs) > 0 {
		histogram.Record(ctx, value, metric.WithAttributes(attrs...))
	} else {
		histogram.Record(ctx, value)
	}
}

// ScopedEmitter wraps an Emitter and automatically adds default attributes to all emissions.
// This reduces boilerplate and ensures consistency across metric calls.
type ScopedEmitter struct {
	base     types.Emitter
	defaults map[string]any
}

var _ types.Emitter = (*ScopedEmitter)(nil)

// NewScopedEmitter creates a new ScopedEmitter that wraps the base emitter
// and automatically includes the provided default attributes in all Emit calls.
func NewScopedEmitter(base types.Emitter, defaults map[string]any) *ScopedEmitter {
	return &ScopedEmitter{base: base, defaults: defaults}
}

// Emit implements types.Emitter. It merges default attributes with call-specific
// details (details override defaults if there are conflicts) and delegates to the base emitter.
func (s *ScopedEmitter) Emit(event string, details map[string]any) {
	merged := make(map[string]any, len(s.defaults)+len(details))
	for k, v := range s.defaults {
		merged[k] = v
	}
	for k, v := range details {
		merged[k] = v
	}
	s.base.Emit(event, merged)
}

// WithDefaults creates a new ScopedEmitter with additional default attributes.
// The new defaults are merged with existing ones (new values override old ones).
func (s *ScopedEmitter) WithDefaults(additional map[string]any) *ScopedEmitter {
	newDefaults := make(map[string]any, len(s.defaults)+len(additional))
	for k, v := range s.defaults {
		newDefaults[k] = v
	}
	for k, v := range additional {
		newDefaults[k] = v
	}
	return &ScopedEmitter{base: s.base, defaults: newDefaults}
}
