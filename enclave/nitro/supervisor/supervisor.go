package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

// crashReportTimeout bounds the post-mortem so an unresponsive host cannot hold
// the enclave VM open indefinitely after the app has already died.
const crashReportTimeout = 10 * time.Second

// reportSink delivers the post-mortem. Indirected so tests can exercise the
// supervise loop without a vsock peer.
var reportSink = sendCrashReport

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
	conn, err := vsock.Dial(types.ProxyParentCID, types.CrashReportPort, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot dial host for crash report: %v\n", err)
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup

	if err := conn.SetDeadline(time.Now().Add(crashReportTimeout)); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot set crash report deadline: %v\n", err)
		return
	}
	if err := json.NewEncoder(conn).Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot send crash report: %v\n", err)
	}
}
