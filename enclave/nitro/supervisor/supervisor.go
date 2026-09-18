package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// crashReportTimeout bounds the entire post-mortem — dial, send and ACK — so an
// unresponsive host cannot hold the enclave VM open after the app has died.
const crashReportTimeout = 10 * time.Second

// reportSink delivers the post-mortem. Indirected so tests can exercise the
// supervise loop without a vsock peer.
var reportSink = sendCrashReport

// dialHost opens the connection to the host's crash report listener. Indirected
// because vsock.Dial fails immediately on non-Linux hosts, which would leave the
// timeout and abandoned-dial paths in dialCrashReport untested.
var dialHost = func() (net.Conn, error) {
	return vsock.Dial(types.ProxyParentCID, types.CrashReportPort, nil)
}

// supervise runs app as a child process and, once it exits, reports its status
// to the host. It returns the child's exit code, which the enclave init in turn
// takes as the VM's.
func supervise(app string, args []string) int {
	cmd := exec.Command(app, args...)
	cmd.Stdout = os.Stdout
	// Passed straight through, never retained: the traceback stays on the enclave
	// console and only the exit status crosses to the host. See types.CrashReport.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot start enclave app: %v\n", err)
		return 1
	}

	stopForwarding := forwardSignals(cmd)
	waitErr := cmd.Wait()
	stopForwarding()

	report := buildCrashReport(filepath.Base(app), cmd.ProcessState, waitErr)
	reportSink(report)
	return report.ExitCode
}

// forwardSignals relays termination signals to the child, since the supervisor
// has taken the entrypoint slot and receives the ones the application would
// otherwise get. It returns a function that stops forwarding.
func forwardSignals(cmd *exec.Cmd) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case sig := <-sigCh:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
		})
	}
}

func buildCrashReport(app string, state *os.ProcessState, waitErr error) types.CrashReport {
	report := types.CrashReport{App: app}

	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		// Wait failed rather than reporting a status. Without this the failure
		// would be indistinguishable from a startup guard's exit 1.
		report.Error = waitErr.Error()
		report.ExitCode = 1
	}

	if state == nil {
		return report
	}

	// Prefer os.ProcessState's own rendering over reformatting the wait status by
	// hand: it also reports a core dump, and the stop/continue cases that would
	// otherwise fall through as a bare exit code of -1.
	report.Status = state.String()
	report.ExitCode = state.ExitCode()

	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// ExitCode is -1 for a signalled process. Normalise to 128+signal, which
		// is what the enclave init reports as the VM's own status.
		report.Signal = status.Signal().String()
		report.ExitCode = 128 + int(status.Signal())
	}

	return report
}

func sendCrashReport(report types.CrashReport) {
	// One budget for the whole exchange. The supervisor is holding the enclave VM
	// open across all of it, so a host that misbehaves in any way delays the
	// enclave's restart by at most this long.
	deadline := time.Now().Add(crashReportTimeout)

	conn, err := dialCrashReport(time.Until(deadline))
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot dial host for crash report: %v\n", err)
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup

	if err := writeCrashReport(conn, report, deadline); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: %v\n", err)
	}
}

// dialCrashReport connects to the host listener, bounded by timeout.
//
// vsock.Dial carries no deadline of its own and SetDeadline cannot be applied
// until it returns, so connect() to a host that is listening but not accepting
// would block indefinitely — keeping a dead enclave alive rather than letting it
// restart. Mirrors the bounded-dial pattern in nitro/proxy-client.
func dialCrashReport(timeout time.Duration) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := dialHost()
		resultCh <- dialResult{conn: conn, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-timer.C:
		// Abandon the dial, closing the connection if it lands later so the
		// goroutine does not leave a socket open behind us.
		go func() {
			if result := <-resultCh; result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, fmt.Errorf("dial timed out after %s", timeout)
	}
}

// writeCrashReport sends the report and blocks until the host acknowledges it.
//
// Waiting for the ACK is the delivery guarantee. Encode returning nil proves
// only that the bytes reached the local socket buffer; once this process exits,
// the init that forked it reboots and the VM — along with any unread data still
// in flight — is destroyed. Returning only after the host has confirmed it
// logged the report keeps the enclave alive across that window.
//
// deadline is the caller's overall budget, shared with the dial, so the total
// hold on the VM stays bounded however the host misbehaves.
func writeCrashReport(conn net.Conn, report types.CrashReport, deadline time.Time) error {
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("cannot set crash report deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(report); err != nil {
		return fmt.Errorf("cannot send crash report: %w", err)
	}

	ack := make([]byte, len(types.CrashReportAck))
	if _, err := io.ReadFull(conn, ack); err != nil {
		return fmt.Errorf("crash report not acknowledged: %w", err)
	}
	if string(ack) != types.CrashReportAck {
		return fmt.Errorf("unexpected crash report acknowledgement %q", ack)
	}

	return nil
}
