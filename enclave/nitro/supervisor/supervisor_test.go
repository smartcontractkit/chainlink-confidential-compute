package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// superviseTestChildEnv selects the crash shape for the re-executed copy of this
// test binary that stands in for the enclave application.
const superviseTestChildEnv = "CC_SUPERVISOR_TEST_CHILD"

// A signalled child is how a wasmtime SIGSEGV or an OOM kill presents, and
// ExitCode reports -1 for it, so the signal has to be recovered separately.
func TestBuildCrashReport_SignalledChild(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sh", "-c", "kill -SEGV $$")
	waitErr := cmd.Run()
	require.Error(t, waitErr)

	report := buildCrashReport("enclave-app", cmd.ProcessState, waitErr)
	assert.Equal(t, "enclave-app", report.App)
	assert.Equal(t, syscall.SIGSEGV.String(), report.Signal)
	assert.Equal(t, 128+int(syscall.SIGSEGV), report.ExitCode)
	// ProcessState's rendering carries the signal name, and " (core dumped)"
	// when the kernel dumped, which the structured fields cannot express.
	assert.Contains(t, report.Status, "signal: "+syscall.SIGSEGV.String())
	assert.Empty(t, report.Error, "an exit status is not a Wait failure")
}

func TestBuildCrashReport_NonZeroExit(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sh", "-c", "exit 3")
	waitErr := cmd.Run()
	require.Error(t, waitErr)

	report := buildCrashReport("enclave-app", cmd.ProcessState, waitErr)
	assert.Equal(t, 3, report.ExitCode)
	assert.Empty(t, report.Signal)
	assert.Equal(t, "exit status 3", report.Status)
	assert.Empty(t, report.Error)
}

func TestBuildCrashReport_CleanExitStillReported(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sh", "-c", "exit 0")
	require.NoError(t, cmd.Run())

	report := buildCrashReport("enclave-app", cmd.ProcessState, nil)
	assert.Equal(t, 0, report.ExitCode)
	assert.Equal(t, "exit status 0", report.Status)
	assert.Empty(t, report.Signal)
	assert.Empty(t, report.Error)
}

// Wait failing is not an exit status: there is no process state to read, so the
// error text is the only thing distinguishing it from a startup guard's exit 1.
func TestBuildCrashReport_WaitFailure(t *testing.T) {
	t.Parallel()

	report := buildCrashReport("enclave-app", nil, errors.New("wait blew up"))
	assert.Equal(t, 1, report.ExitCode)
	assert.Equal(t, "wait blew up", report.Error)
	assert.Empty(t, report.Status)
}

// The report has to survive a JSON round trip over vsock, and must not regain a
// stderr field: the host is outside the enclave's trust boundary.
func TestCrashReport_RoundTripsOverAConnection(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	want := types.CrashReport{
		App:      "enclave-app",
		ExitCode: 137,
		Signal:   "killed",
		Status:   "signal: killed",
	}

	go func() { _ = json.NewEncoder(client).Encode(want) }()

	var got types.CrashReport
	require.NoError(t, json.NewDecoder(server).Decode(&got))
	assert.Equal(t, want, got)

	encoded, err := json.Marshal(want)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "stderr")
}

// TestSupervise_EndToEnd drives the real supervise loop: it runs a child that
// dies, and the supervisor must outlive it and report its status. This is the
// property the whole design rests on — AWS's enclave init reboots the VM as soon
// as the process it forked exits, so the supervisor holding that slot is what
// buys the window to report at all.
//
// Two crash shapes, because they present differently:
//   - "fatal": what a cgo SIGSEGV actually looks like. Go's runtime catches the
//     signal, prints to stderr and exits 2, so the wait status carries no signal.
//   - "killed": an uncatchable signal, as an OOM kill of the enclave presents.
func TestSupervise_EndToEnd(t *testing.T) {
	switch os.Getenv(superviseTestChildEnv) {
	case "fatal":
		fmt.Fprintln(os.Stderr, "fatal error: unexpected signal during runtime execution")
		fmt.Fprintln(os.Stderr, "[signal SIGSEGV: segmentation violation]")
		os.Exit(2)
	case "killed":
		fmt.Fprintln(os.Stderr, "panic: simulated enclave crash")
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {} // unreachable once the signal lands
	}

	for name, tc := range map[string]struct {
		mode       string
		wantSignal string
		wantCode   int
		wantStatus string
	}{
		"go runtime fatal": {
			mode:       "fatal",
			wantCode:   2,
			wantStatus: "exit status 2",
		},
		"uncatchable signal": {
			mode:       "killed",
			wantSignal: syscall.SIGKILL.String(),
			wantCode:   128 + int(syscall.SIGKILL),
			wantStatus: "signal: " + syscall.SIGKILL.String(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Stand in for the enclave app with this test binary, re-entered in
			// the mode that produces the crash shape under test.
			self, err := os.Executable()
			require.NoError(t, err)
			t.Setenv(superviseTestChildEnv, tc.mode)

			got := make(chan types.CrashReport, 1)
			origSink := reportSink
			reportSink = func(r types.CrashReport) { got <- r }
			t.Cleanup(func() { reportSink = origSink })

			code := supervise(self, []string{"-test.run=TestSupervise_EndToEnd"})

			select {
			case report := <-got:
				assert.Equal(t, tc.wantSignal, report.Signal)
				assert.Equal(t, tc.wantCode, report.ExitCode)
				assert.Equal(t, tc.wantStatus, report.Status)
				assert.Equal(t, report.ExitCode, code, "supervisor should surface the child's status")
			default:
				t.Fatal("supervisor produced no crash report")
			}
		})
	}
}
