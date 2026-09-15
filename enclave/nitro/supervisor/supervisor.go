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

	report := buildCrashReport(filepath.Base(app), waitErr)
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

func buildCrashReport(app string, waitErr error) types.CrashReport {
	report := types.CrashReport{App: app}

	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		// The enclave server blocks forever, so even a clean exit is unexpected.
	case errors.As(waitErr, &exitErr):
		report.ExitCode = exitErr.ExitCode()
		// ExitCode reports -1 for a signalled process; recover the signal instead,
		// which is how a wasmtime SIGSEGV or an OOM kill presents.
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			report.Signal = status.Signal().String()
			report.ExitCode = 128 + int(status.Signal())
		}
	default:
		report.Error = waitErr.Error()
		report.ExitCode = 1
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
