package main

import (
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

func TestHandleCrashReport_LogsTheReport(t *testing.T) {
	t.Parallel()

	lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	report := types.CrashReport{
		App:          "enclave-app",
		ExitCode:     137,
		Signal:       "killed",
		Status:       "signal: killed",
		PeakRSSBytes: 10 << 30,
	}
	ack := make(chan string, 1)
	go func() {
		_ = json.NewEncoder(client).Encode(report)
		buf := make([]byte, len(types.CrashReportAck))
		if _, err := io.ReadFull(client, buf); err != nil {
			ack <- ""
			return
		}
		ack <- string(buf)
	}()

	handleCrashReport(server, lggr, nil)

	entries := logs.FilterMessage("enclave application exited").All()
	require.Len(t, entries, 1)

	fields := entries[0].ContextMap()
	assert.Equal(t, "enclave-app", fields["app"])
	assert.EqualValues(t, 137, fields["exitCode"])
	assert.Equal(t, "killed", fields["signal"])
	assert.Equal(t, "signal: killed", fields["status"])
	assert.EqualValues(t, uint64(10<<30), fields["peakRSSBytes"])
	assert.NotContains(t, fields, "stderrTail", "stderr must not cross the trust boundary")

	// The supervisor is holding the enclave VM open until this arrives.
	select {
	case got := <-ack:
		assert.Equal(t, types.CrashReportAck, got)
	case <-time.After(10 * time.Second):
		t.Fatal("crash report was never acknowledged")
	}
}

func TestHandleCrashReport_MalformedPayload(t *testing.T) {
	t.Parallel()

	lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		_, _ = client.Write([]byte("not json"))
		_ = client.Close()
	}()

	handleCrashReport(server, lggr, nil)

	assert.Len(t, logs.FilterMessage("enclave application exited").All(), 0)
	assert.Len(t, logs.FilterMessage("failed to decode enclave crash report").All(), 1)
}

// An oversized payload must not be buffered without bound.
func TestHandleCrashReport_RejectsOversizePayload(t *testing.T) {
	t.Parallel()

	lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		defer client.Close() //nolint:errcheck // test cleanup
		// Valid JSON prefix, then more bytes than the limit allows.
		_, _ = client.Write([]byte(`{"app":"`))
		chunk := strings.Repeat("a", 64<<10)
		for range (crashReportMaxBytes / len(chunk)) + 2 {
			if _, err := client.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); handleCrashReport(server, lggr, nil) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("handleCrashReport did not return on an oversize payload")
	}

	assert.Len(t, logs.FilterMessage("enclave application exited").All(), 0)
	assert.Len(t, logs.FilterMessage("failed to decode enclave crash report").All(), 1)
}

func TestServeCrashReports_ReturnsOnClosedListener(t *testing.T) {
	t.Parallel()

	lggr := logger.Test(t)
	listener := newPipeListener()

	errCh := make(chan error, 1)
	go func() { errCh <- serveCrashReports(listener, lggr, nil) }()

	require.NoError(t, listener.Close())

	select {
	case err := <-errCh:
		// A closed listener is an orderly shutdown, not a failure to report.
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("serveCrashReports did not return after the listener closed")
	}
}

// pipeListener is a net.Listener that never yields a connection and reports
// net.ErrClosed once closed.
type pipeListener struct{ closed chan struct{} }

func newPipeListener() *pipeListener { return &pipeListener{closed: make(chan struct{})} }

func (l *pipeListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *pipeListener) Close() error {
	close(l.closed)
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "unix"} }

// TestHandleCrashReport_RecordsMetric covers the alerting path: a log line is
// awkward to alert on, so an enclave app exit must also increment a counter
// dimensioned by cause. This is the only host-side signal that an enclave died,
// since the enclave init reboots the VM with the status and describe-enclaves
// exposes no exit code for a terminated enclave.
func TestHandleCrashReport_RecordsMetric(t *testing.T) {
	for name, tc := range map[string]struct {
		report    types.CrashReport
		wantAttrs []attribute.KeyValue
	}{
		"oom kill shape": {
			report:    types.CrashReport{App: "enclave-app", ExitCode: 137, Signal: "killed", Status: "signal: killed"},
			wantAttrs: []attribute.KeyValue{attribute.Int("exit.code", 137), attribute.String("signal", "killed")},
		},
		"runtime fatal error": {
			// No signal reaches the wait status, so the attribute is omitted
			// rather than recorded empty.
			report:    types.CrashReport{App: "enclave-app", ExitCode: 2, Status: "exit status 2"},
			wantAttrs: []attribute.KeyValue{attribute.Int("exit.code", 2)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			metrics, reader := newTestHostMetrics(t)
			lggr := logger.Test(t)

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })
			go func() {
				_ = json.NewEncoder(client).Encode(tc.report)
				buf := make([]byte, len(types.CrashReportAck))
				_, _ = io.ReadFull(client, buf)
			}()

			handleCrashReport(server, lggr, metrics)

			data := collectHostMetrics(t, reader)
			exits := requireMetric(t, data, "confidential_compute.enclave.app.exits")
			sum, ok := exits.Data.(metricdata.Sum[int64])
			require.True(t, ok, "app exits should be a counter")
			require.Len(t, sum.DataPoints, 1)
			assert.EqualValues(t, 1, sum.DataPoints[0].Value)
			assert.ElementsMatch(t, tc.wantAttrs, sum.DataPoints[0].Attributes.ToSlice())
		})
	}
}

// A report the host could not decode must not be counted, or a malformed peer
// would look like a stream of enclave deaths.
func TestHandleCrashReport_MalformedPayloadRecordsNoMetric(t *testing.T) {
	metrics, reader := newTestHostMetrics(t)
	lggr := logger.Test(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		_, _ = client.Write([]byte("not json"))
		_ = client.Close()
	}()

	handleCrashReport(server, lggr, metrics)

	data := collectHostMetrics(t, reader)
	_, found := findMetric(data, "confidential_compute.enclave.app.exits")
	assert.False(t, found, "a report that failed to decode must not be counted")
}
