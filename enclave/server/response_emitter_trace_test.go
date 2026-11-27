package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/stretchr/testify/require"
)

// TestResponseEmitterMirrorsEventsIntoTheTraceRing checks that an event is in
// the ring file as soon as it is emitted, labelled with its request.
func TestResponseEmitterMirrorsEventsIntoTheTraceRing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(crashdebug.EnvCrashDir, dir)
	crashdebug.Init(t.Logf)
	require.True(t, crashdebug.Enabled())

	first, second := NewResponseEmitter(), NewResponseEmitter()
	require.NotEqual(t, first.traceLabel(), second.traceLabel())
	first.Emit("request_started", map[string]any{"endpoint": "execute"})
	first.Emit("request_id", map[string]any{"request_id": "aabbccddeeff00112233445566778899"})
	first.Emit("capability_started", map[string]any{"method": "SendRequest", "capability_id": "http-actions@1.0.0", "step_ref": int32(3)})
	second.Emit("request_started", nil)
	// An emitter built without the constructor still traces.
	(&ResponseEmitter{}).Emit("orphan", nil)

	ring, err := os.ReadFile(filepath.Join(dir, crashdebug.TraceRingFile))
	require.NoError(t, err)
	records, err := crashdebug.ReadRing(ring, 0)
	require.NoError(t, err)
	var trace strings.Builder
	for _, rec := range records {
		trace.WriteString(rec.Msg + "\n")
	}

	label := first.traceLabel()
	require.Contains(t, label, " rid=aabbccddeeff0011")
	base, _, _ := strings.Cut(label, " ")
	require.Contains(t, trace.String(), base+" request_started endpoint=execute\n")
	// Details are sorted by key, so the same event always reads the same.
	require.Contains(t, trace.String(), label+" capability_started capability_id=http-actions@1.0.0 method=SendRequest step_ref=3\n")
	require.Contains(t, trace.String(), second.traceLabel()+" request_started\n")
	require.Contains(t, trace.String(), "em#? orphan\n")

	// The response still carries the events as before.
	require.Len(t, first.GetMetricEvents(), 3)
}
