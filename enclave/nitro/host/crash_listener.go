package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const (
	// crashReportReadTimeout bounds a single report read so a stuck connection
	// cannot occupy the listener.
	crashReportReadTimeout = 30 * time.Second

	// crashReportMaxBytes caps a single report. The supervisor retains 256KiB of
	// stderr; this leaves headroom for the JSON envelope while refusing anything
	// that could only be a misbehaving peer.
	crashReportMaxBytes = 1 << 20
)

// serveCrashReports accepts enclave post-mortems until the listener is closed.
//
// The enclave application is PID 1 in its VM, so its stderr dies with it and the
// Nitro console is unreadable without --debug-mode. Its supervisor ships the tail
// here instead, which is the only way a panic traceback or a wasmtime SIGSEGV
// reaches host logs. Reports are logged at error level so they land in Loki
// alongside the rest of the host's output.
func ServeCrashReports(listener net.Listener, lggr logger.Logger) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleCrashReport(conn, lggr)
	}
}

func handleCrashReport(conn net.Conn, lggr logger.Logger) {
	defer conn.Close() //nolint:errcheck // best-effort cleanup

	if err := conn.SetReadDeadline(time.Now().Add(crashReportReadTimeout)); err != nil {
		lggr.Errorw("failed to set crash report read deadline", "error", err)
		return
	}

	var report types.CrashReport
	if err := json.NewDecoder(io.LimitReader(conn, crashReportMaxBytes)).Decode(&report); err != nil {
		lggr.Errorw("failed to decode enclave crash report", "error", err)
		return
	}

	lggr.Errorw("enclave application exited",
		"app", report.App,
		"exitCode", report.ExitCode,
		"signal", report.Signal,
		"waitError", report.Error,
		"stderrTruncated", report.Truncated,
		"stderrTail", report.StderrTail,
	)
}
