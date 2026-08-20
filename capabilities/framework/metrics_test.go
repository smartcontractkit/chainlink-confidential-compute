package framework

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowedAttribute(t *testing.T) {
	allowed := []string{
		"component", "enclave.id", "endpoint", "outcome", "status_code",
		"capability_id", "method", "step_ref", "success", "error_type",
		"num_signatures", "num_ciphertexts", "num_requests",
		"max_concurrent", "metric_type", "workflow_id",
	}
	for _, k := range allowed {
		assert.True(t, allowedAttribute(k), "expected %q to be allowed", k)
	}

	// High-cardinality / author-controlled / free-text keys must be dropped.
	dropped := []string{
		"request_id", "message", "error", "name", "value",
		"execution_id", "label.foo", "label.tx_hash",
		"output_bytes",
	}
	for _, k := range dropped {
		assert.False(t, allowedAttribute(k), "expected %q to be dropped", k)
	}
}

func TestDroppedMetricEvents(t *testing.T) {
	// request_id's only payload is the per-request ID; it must never become a metric.
	assert.Contains(t, droppedMetricEvents, "request_id")
}
