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
		App:      "enclave-app",
		ExitCode: 137,
		Signal:   "killed",
		Status:   "signal: killed",
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

	handleCrashReport(server, lggr)

	entries := logs.FilterMessage("enclave application exited").All()
	require.Len(t, entries, 1)

	fields := entries[0].ContextMap()
	assert.Equal(t, "enclave-app", fields["app"])
	assert.EqualValues(t, 137, fields["exitCode"])
	assert.Equal(t, "killed", fields["signal"])
	assert.Equal(t, "signal: killed", fields["status"])
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

	handleCrashReport(server, lggr)

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
	go func() { defer close(done); handleCrashReport(server, lggr) }()

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
	go func() { errCh <- ServeCrashReports(listener, lggr) }()

	require.NoError(t, listener.Close())

	select {
	case err := <-errCh:
		// A closed listener is an orderly shutdown, not a failure to report.
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("ServeCrashReports did not return after the listener closed")
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
