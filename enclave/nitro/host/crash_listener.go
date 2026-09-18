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

	// crashReportMaxBytes caps a single report. The payload is exit status only,
	// so anything beyond a few hundred bytes is a misbehaving peer.
	crashReportMaxBytes = 4 << 10
)

// serveCrashReports accepts enclave post-mortems until the listener is closed.
//
// The enclave's exit status is otherwise unrecoverable host-side: the enclave
// init computes it and then reboots the VM, and describe-enclaves exposes no
// exit code for a terminated enclave. The supervisor relays it here instead.
// Reports are logged at error level so they land in Loki alongside the rest of
// the host's output.
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

	// Status only: the traceback stays inside the enclave, since the host is
	// outside its trust boundary. See types.CrashReport.
	lggr.Errorw("enclave application exited",
		"app", report.App,
		"exitCode", report.ExitCode,
		"signal", report.Signal,
		"status", report.Status,
		"waitError", report.Error,
	)
}
