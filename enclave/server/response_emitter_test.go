package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repeated events (e.g. one capability_execution per call) must survive as
// distinct entries in the ordered list, even though the name-keyed map collapses
// them. This is what lets the host re-emit N counter increments instead of one.
func TestResponseEmitter_MetricEventsPreserveDuplicates(t *testing.T) {
	e := NewResponseEmitter()
	e.Emit("capability_execution", map[string]any{"capability_id": "a"})
	e.Emit("capability_execution", map[string]any{"capability_id": "b"})
	e.Emit("get_secrets", map[string]any{"success": true})

	events := e.GetMetricEvents()
	require.Len(t, events, 3, "list preserves every occurrence")
	assert.Equal(t, "a", events[0].Details["capability_id"])
	assert.Equal(t, "b", events[1].Details["capability_id"])

	m := e.GetMetrics()
	require.Len(t, m, 2, "map collapses same-named events to the last one")
	assert.Equal(t, "b", m["capability_execution"].(map[string]any)["capability_id"])
}

func TestResponseEmitter_ErrorResponseCarriesMetricEvents(t *testing.T) {
	e := NewResponseEmitter()
	e.Emit("capability_execution", map[string]any{"capability_id": "a"})
	e.Emit("capability_execution", map[string]any{"capability_id": "b"})

	// WriteErrorResponse appends its own request_completed event and must carry
	// the full ordered list (2 capability_execution + 1 request_completed).
	require.Len(t, e.GetMetricEvents(), 2)
}
