package server

import (
	"encoding/json"
	"math"
	"net/http"
	"time"

	"github.com/smartcontractkit/confidential-compute/types"
)

// durationBucketSeconds defines the rounding granularity for timing metrics.
// Durations are rounded to the nearest 10ms to reduce timing side-channel resolution.
const durationBucketSeconds = 0.01

// ResponseEmitter collects metrics to be included in the response payload
// instead of emitting them via OTel.
type ResponseEmitter struct {
	metrics []types.MetricEvent
	// Captured at construction so WriteErrorResponse can report the total request
	// duration on error, not just on the success path.
	startTime time.Time
}

// Ensure ResponseEmitter implements types.Emitter
var _ types.Emitter = (*ResponseEmitter)(nil)

func NewResponseEmitter() *ResponseEmitter {
	return &ResponseEmitter{
		metrics:   make([]types.MetricEvent, 0),
		startTime: time.Now(),
	}
}

func (e *ResponseEmitter) Emit(event string, details map[string]any) {
	e.metrics = append(e.metrics, types.MetricEvent{
		Event:   event,
		Details: roundDurations(details),
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
	result := make(map[string]any)
	for _, m := range e.metrics {
		result[m.Event] = m.Details
	}
	return result
}

// GetMetricEvents returns every collected event in order, preserving duplicates.
func (e *ResponseEmitter) GetMetricEvents() []types.MetricEvent {
	return e.metrics
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
	resp := types.EnclaveErrorResponse{
		Error:        msg,
		Metrics:      e.GetMetrics(),
		MetricEvents: e.GetMetricEvents(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}
