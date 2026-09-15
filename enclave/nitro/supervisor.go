package nitro

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// reportSink delivers the post-mortem. Indirected so tests can exercise the
// supervise loop without a vsock peer.
var reportSink = sendCrashReport

const (
	superviseFlagName = "supervise"

	// superviseEnv marks the re-executed child so it can never itself supervise.
	// The child's argv already has the flag stripped; this is a hard stop against
	// an unbounded re-exec loop inside the enclave if that ever fails.
	superviseEnv = "CC_ENCLAVE_SUPERVISED"

	// crashLogBytes is how much of the child's stderr is retained for the report.
	// A Go traceback for a few dozen goroutines fits comfortably, and the buffer
	// is a rounding error against the enclave's fixed memory.
	crashLogBytes = 256 << 10

	// crashReportTimeout bounds the post-mortem so an unresponsive host cannot
	// hold the enclave VM open indefinitely after the app has already died.
	crashReportTimeout = 10 * time.Second
)

var superviseFlag = flag.Bool(superviseFlagName, false,
	"Run as a supervisor: exec the enclave app as a child and forward its stderr to the host if it exits.")

// SuperviseIfRequested takes over as the supervisor and never returns when
// --supervise is set. Otherwise it returns immediately and the caller proceeds
// as the enclave application itself. Call it directly after flag.Parse.
//
// Calling it before any other setup is a correctness requirement, not a
// convention: the supervisor re-execs this binary as a child, so anything built
// beforehand (the NSM session, the keychain, the app itself) would be
// constructed twice and left orphaned in the parent process.
func SuperviseIfRequested() {
	if !supervising() {
		return
	}
	os.Exit(supervise())
}

// supervising reports whether this process should run as the supervisor rather
// than as the enclave application itself.
func supervising() bool {
	return *superviseFlag && os.Getenv(superviseEnv) != "1"
}

// supervise runs the enclave application as a child process and, once it exits,
// ships the tail of its stderr to the host. It returns the child's exit code.
//
// The enclave application is PID 1 in the Nitro VM, so when it dies the VM is
// torn down with it and its stderr is lost: that output goes to the enclave
// console, which is unreadable unless the enclave was launched with --debug-mode
// (which zeroes the PCRs, breaking attestation). Everything diagnostic lands
// there — Go panic tracebacks, runtime fatal errors, the "unexpected signal
// during runtime execution" report for a SIGSEGV inside cgo, and whatever
// libwasmtime prints on abort.
//
// Interposing a supervisor as PID 1 keeps the VM alive past the application's
// death for long enough to ship that tail to the host over vsock.
func supervise() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot determine own executable: %v\n", err)
		return 1
	}

	tail := newTailBuffer(crashLogBytes)
	cmd := exec.Command(exe, childArgs(os.Args[1:])...)
	cmd.Env = append(os.Environ(), superviseEnv+"=1")
	cmd.Stdout = os.Stdout
	// Tee rather than capture: stderr still reaches the console for debug-mode
	// enclaves and local runs, while the tail is retained for the report.
	cmd.Stderr = io.MultiWriter(os.Stderr, tail)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "supervisor: cannot start enclave app: %v\n", err)
		return 1
	}

	stopForwarding := forwardSignals(cmd)
	waitErr := cmd.Wait()
	stopForwarding()

	report := buildCrashReport(filepath.Base(exe), waitErr, tail)
	reportSink(report)
	return report.ExitCode
}

// forwardSignals relays termination signals to the child, since as PID 1 the
// supervisor receives the ones the application would otherwise get. It returns a
// function that stops forwarding.
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

// childArgs drops the supervise flag so the child runs as the application. Go's
// flag package requires `-bool=value` rather than `-bool value`, so a bare name
// or a name= prefix covers every form.
func childArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		name := strings.TrimLeft(arg, "-")
		if name == superviseFlagName || strings.HasPrefix(name, superviseFlagName+"=") {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func buildCrashReport(app string, waitErr error, tail *tailBuffer) types.CrashReport {
	body, truncated := tail.Tail()
	report := types.CrashReport{
		App:        app,
		StderrTail: string(body),
		Truncated:  truncated,
	}

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

// tailBuffer retains the last size bytes written to it, dropping from the front.
type tailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	size      int
	truncated bool
}

func newTailBuffer(size int) *tailBuffer {
	return &tailBuffer{buf: make([]byte, 0, size), size: size}
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := len(p)
	if n >= t.size {
		t.buf = append(t.buf[:0], p[n-t.size:]...)
		t.truncated = true
		return n, nil
	}
	if overflow := len(t.buf) + n - t.size; overflow > 0 {
		t.buf = append(t.buf[:0], t.buf[overflow:]...)
		t.truncated = true
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

// Tail returns a copy of the retained bytes and whether anything was dropped.
func (t *tailBuffer) Tail() ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]byte, len(t.buf))
	copy(out, t.buf)
	return out, t.truncated
}
