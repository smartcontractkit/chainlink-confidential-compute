package server

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// durationBucketSeconds defines the rounding granularity for timing metrics.
// Durations are rounded to the nearest 10ms to reduce timing side-channel resolution.
const durationBucketSeconds = 0.01

// ResponseEmitter collects metrics to be included in the response payload
// instead of emitting them via OTel.
type ResponseEmitter struct {
	mu      sync.RWMutex
	metrics []types.MetricEvent
	// Captured at construction so WriteErrorResponse can report the total request
	// duration on error, not just on the success path.
	startTime time.Time
	// traceTag labels this request's records in the debug trace ring.
	traceTag atomic.Pointer[string]
}

// emitterSeq numbers the emitters so trace records of concurrent requests can
// be told apart before their request ID is known.
var emitterSeq atomic.Uint64

// Ensure ResponseEmitter implements types.Emitter
var _ types.Emitter = (*ResponseEmitter)(nil)

func NewResponseEmitter() *ResponseEmitter {
	e := &ResponseEmitter{
		metrics:   make([]types.MetricEvent, 0),
		startTime: time.Now(),
	}
	tag := fmt.Sprintf("em#%d", emitterSeq.Add(1))
	e.traceTag.Store(&tag)
	return e
}

// traceLabel is this request's label in the debug trace ring.
func (e *ResponseEmitter) traceLabel() string {
	if tag := e.traceTag.Load(); tag != nil {
		return *tag
	}
	return "em#?"
}

// trace mirrors an event into the debug trace ring, unrounded, at the moment
// it happens rather than when the response is assembled.
func (e *ResponseEmitter) trace(event string, details map[string]any) {
	if rid, ok := details["request_id"].(string); ok && event == "request_id" {
		tag := e.traceLabel() + " rid=" + rid[:min(len(rid), 16)]
		e.traceTag.Store(&tag)
	}
	var b strings.Builder
	for _, key := range slices.Sorted(maps.Keys(details)) {
		fmt.Fprintf(&b, " %s=%v", key, details[key])
	}
	crashdebug.Tracef("%s %s%s", e.traceLabel(), event, b.String())
}

func (e *ResponseEmitter) Emit(event string, details map[string]any) {
	if crashdebug.Enabled() {
		e.trace(event, details)
	}
	details = roundDurations(maps.Clone(details))

	e.mu.Lock()
	defer e.mu.Unlock()
	e.metrics = append(e.metrics, types.MetricEvent{
		Event:   event,
		Details: details,
	})
}

// roundDurations rounds any "duration_seconds" values in the details map to
// the nearest durationBucketSeconds to reduce timing resolution.
func roundDurations(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	for k, v := range details {
		if k == "duration_seconds" {
			if f, ok := v.(float64); ok {
				details[k] = math.Round(f/durationBucketSeconds) * durationBucketSeconds
			}
		}
	}
	return details
}

// GetMetrics returns all collected metrics as a map keyed by event name.
// Duplicate event names collapse to the last occurrence; use GetMetricEvents
// when per-occurrence counts matter (e.g. repeated capability calls).
func (e *ResponseEmitter) GetMetrics() map[string]any {
	metrics, _ := e.Snapshot()
	return metrics
}

// GetMetricEvents returns every collected event in order, preserving duplicates.
func (e *ResponseEmitter) GetMetricEvents() []types.MetricEvent {
	_, events := e.Snapshot()
	return events
}

// Snapshot returns consistent map and ordered representations of all events.
func (e *ResponseEmitter) Snapshot() (map[string]any, []types.MetricEvent) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	metrics := make(map[string]any)
	events := make([]types.MetricEvent, len(e.metrics))
	for i, event := range e.metrics {
		details := maps.Clone(event.Details)
		events[i] = types.MetricEvent{Event: event.Event, Details: details}
		metrics[event.Event] = details
	}
	return metrics, events
}

// WriteErrorResponse writes a JSON error response that includes the accumulated
// metrics so the host can still forward them to Prometheus. Plain http.Error
// returns text/plain and loses the metrics entirely.
func (e *ResponseEmitter) WriteErrorResponse(w http.ResponseWriter, msg string, statusCode int) {
	// Record the total request duration even on error; the enclave-client forwards
	// it to OTel as request_completed with enclave tagging, and Emit applies the 10ms rounding.
	// endpoint is fixed because this emitter is only used by the execute handler.
	e.Emit("request_completed", map[string]any{
		"endpoint":         "execute",
		"outcome":          "error",
		"status_code":      statusCode,
		"duration_seconds": time.Since(e.startTime).Seconds(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	metrics, metricEvents := e.Snapshot()
	resp := types.EnclaveErrorResponse{
		Error:        msg,
		Metrics:      metrics,
		MetricEvents: metricEvents,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
