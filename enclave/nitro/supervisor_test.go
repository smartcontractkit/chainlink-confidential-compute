package nitro

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// superviseTestChildEnv marks the re-executed copy of this test binary as the
// supervised child.
const superviseTestChildEnv = "CC_SUPERVISOR_TEST_CHILD"

func TestChildArgs_StripsSuperviseFlag(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		in   []string
		want []string
	}{
		"single dash":      {[]string{"-supervise", "--vsock-port=5000"}, []string{"--vsock-port=5000"}},
		"double dash":      {[]string{"--supervise", "--vsock-port=5000"}, []string{"--vsock-port=5000"}},
		"explicit true":    {[]string{"--supervise=true"}, []string{}},
		"explicit false":   {[]string{"-supervise=false", "--allow-reconfig"}, []string{"--allow-reconfig"}},
		"absent":           {[]string{"--vsock-port=5000"}, []string{"--vsock-port=5000"}},
		"no args":          {nil, []string{}},
		"similar flagname": {[]string{"--supervise-other=1"}, []string{"--supervise-other=1"}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, childArgs(tc.in))
		})
	}
}

func TestTailBuffer_RetainsTailAndFlagsTruncation(t *testing.T) {
	t.Parallel()

	t.Run("under capacity keeps everything", func(t *testing.T) {
		b := newTailBuffer(16)
		_, err := b.Write([]byte("hello"))
		require.NoError(t, err)
		out, truncated := b.Tail()
		assert.Equal(t, "hello", string(out))
		assert.False(t, truncated)
	})

	t.Run("drops from the front across writes", func(t *testing.T) {
		b := newTailBuffer(8)
		for _, s := range []string{"aaaa", "bbbb", "cccc"} {
			_, err := b.Write([]byte(s))
			require.NoError(t, err)
		}
		out, truncated := b.Tail()
		assert.Equal(t, "bbbbcccc", string(out))
		assert.True(t, truncated)
	})

	t.Run("single oversized write keeps the tail", func(t *testing.T) {
		b := newTailBuffer(4)
		_, err := b.Write([]byte("abcdefgh"))
		require.NoError(t, err)
		out, truncated := b.Tail()
		assert.Equal(t, "efgh", string(out))
		assert.True(t, truncated)
	})

	t.Run("reports full write length to satisfy io.Writer", func(t *testing.T) {
		b := newTailBuffer(4)
		n, err := b.Write([]byte("abcdefgh"))
		require.NoError(t, err)
		assert.Equal(t, 8, n, "a short write would make io.MultiWriter abort the tee")
	})
}

// A signalled child is how a wasmtime SIGSEGV or an OOM kill presents, and
// ExitCode reports -1 for it, so the signal has to be recovered separately.
func TestBuildCrashReport_SignalledChild(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sh", "-c", "kill -SEGV $$")
	waitErr := cmd.Run()
	require.Error(t, waitErr)

	tail := newTailBuffer(64)
	_, err := tail.Write([]byte("panic: boom"))
	require.NoError(t, err)

	report := buildCrashReport("enclave-app", waitErr, tail)
	assert.Equal(t, "enclave-app", report.App)
	assert.Equal(t, "panic: boom", report.StderrTail)
	assert.Equal(t, syscall.SIGSEGV.String(), report.Signal)
	assert.Equal(t, 128+int(syscall.SIGSEGV), report.ExitCode)
}

func TestBuildCrashReport_NonZeroExit(t *testing.T) {
	t.Parallel()

	waitErr := exec.Command("sh", "-c", "exit 3").Run()
	require.Error(t, waitErr)

	report := buildCrashReport("enclave-app", waitErr, newTailBuffer(64))
	assert.Equal(t, 3, report.ExitCode)
	assert.Empty(t, report.Signal)
}

func TestBuildCrashReport_CleanExitStillReported(t *testing.T) {
	t.Parallel()

	report := buildCrashReport("enclave-app", nil, newTailBuffer(64))
	assert.Equal(t, 0, report.ExitCode)
	assert.Empty(t, report.Signal)
	assert.Empty(t, report.Error)
}

func TestBuildCrashReport_WaitFailure(t *testing.T) {
	t.Parallel()

	report := buildCrashReport("enclave-app", errors.New("wait blew up"), newTailBuffer(64))
	assert.Equal(t, 1, report.ExitCode)
	assert.Equal(t, "wait blew up", report.Error)
}

// The report has to survive a JSON round trip over vsock with a realistic
// traceback in it, including the newlines a Go stack dump is made of.
func TestCrashReport_RoundTripsOverAConnection(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	want := types.CrashReport{
		App:        "enclave-app",
		ExitCode:   139,
		Signal:     "segmentation fault",
		StderrTail: "panic: assignment to entry in nil map\n\ngoroutine 42 [running]:\n\tmain.go:1 +0x1",
		Truncated:  true,
	}

	go func() { _ = json.NewEncoder(client).Encode(want) }()

	var got types.CrashReport
	require.NoError(t, json.NewDecoder(server).Decode(&got))
	assert.Equal(t, want, got)
	assert.True(t, strings.Contains(got.StderrTail, "goroutine 42"))
}

// TestSupervise_EndToEnd drives the real supervise loop: the test binary
// re-execs itself, the child writes a traceback to stderr and dies, and the
// supervisor must capture that output and report it rather than losing it the
// way the enclave console does today.
//
// Two shapes, because they present differently:
//   - "fatal": what a cgo SIGSEGV actually looks like. Go's runtime catches the
//     signal, prints "unexpected signal during runtime execution" and exits 2,
//     so there is no signal on the wait status — only the stderr matters.
//   - "killed": an uncatchable signal, as an OOM kill of the enclave presents.
func TestSupervise_EndToEnd(t *testing.T) {
	switch os.Getenv(superviseTestChildEnv) {
	case "fatal":
		fmt.Fprintln(os.Stderr, "fatal error: unexpected signal during runtime execution")
		fmt.Fprintln(os.Stderr, "[signal SIGSEGV: segmentation violation]")
		fmt.Fprintln(os.Stderr, "goroutine 1 [running]:")
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
		wantStderr string
	}{
		"go runtime fatal": {
			mode:       "fatal",
			wantCode:   2,
			wantStderr: "unexpected signal during runtime execution",
		},
		"uncatchable signal": {
			mode:       "killed",
			wantSignal: syscall.SIGKILL.String(),
			wantCode:   128 + int(syscall.SIGKILL),
			wantStderr: "panic: simulated enclave crash",
		},
	} {
		t.Run(name, func(t *testing.T) {
			// supervise() re-execs os.Executable() with os.Args[1:] minus
			// --supervise, so point the child at this test and mark its mode.
			origArgs := os.Args
			os.Args = []string{origArgs[0], "-test.run=TestSupervise_EndToEnd", "--supervise"}
			t.Setenv(superviseTestChildEnv, tc.mode)

			got := make(chan types.CrashReport, 1)
			origSink := reportSink
			reportSink = func(r types.CrashReport) { got <- r }
			t.Cleanup(func() {
				reportSink = origSink
				os.Args = origArgs
			})

			code := supervise()

			select {
			case report := <-got:
				assert.Equal(t, tc.wantSignal, report.Signal)
				assert.Equal(t, tc.wantCode, report.ExitCode)
				assert.Equal(t, report.ExitCode, code, "supervisor should surface the child's status")
				assert.Contains(t, report.StderrTail, tc.wantStderr)
			default:
				t.Fatal("supervisor produced no crash report")
			}
		})
	}
}
