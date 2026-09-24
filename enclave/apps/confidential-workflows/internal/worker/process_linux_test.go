package worker

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestProcessChild(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	fs := flag.NewFlagSet("child", flag.ExitOnError)
	mode := fs.String("mode", "", "")
	length := fs.Int64("job-bytes", 0, "")
	parent := fs.Int("parent-pid", 0, "")
	ready := fs.String("ready-file", "", "")
	_ = fs.Parse(os.Args[i+1:])
	if *parent != os.Getppid() {
		os.Exit(3)
	}
	if *mode == "early" {
		os.Exit(0)
	}
	if *mode == "blocked-input" {
		time.Sleep(time.Hour)
	}
	var job Job
	if err := Decode(os.Stdin, *length, &job, nil); err != nil {
		os.Exit(4)
	}
	if *ready != "" {
		if err := os.WriteFile(*ready, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(7)
		}
	}
	r := successReply(job.RequestID, "hello")
	switch *mode {
	case "panic":
		go func() { panic("test callback panic") }()
		time.Sleep(time.Hour)
	case "abort":
		_ = syscall.Kill(os.Getpid(), syscall.SIGABRT)
		time.Sleep(time.Hour)
	case "hang":
		time.Sleep(time.Hour)
	case "malformed":
		fmt.Fprint(os.Stdout, "not JSON")
		os.Exit(0)
	case "truncated":
		fmt.Fprint(os.Stdout, `{"Version":`)
		os.Exit(0)
	case "oversize":
		fmt.Fprint(os.Stdout, strings.Repeat(" ", MaxReplyBytes+1))
		os.Exit(0)
	case "wrong-id":
		r.RequestID[0] ^= 1
	case "error":
		r.Outcome, r.Result, r.Error = ExecutionError, nil, &types.ExecuteError{Error: types.ErrWasmExecutionTimeout, Code: 504}
	case "large":
		fmt.Fprint(os.Stderr, strings.Repeat("d", 1<<20))
		r = successReply(job.RequestID, strings.Repeat("x", 1<<20))
	case "slow":
		time.Sleep(200 * time.Millisecond)
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestDescendantChild$", "--")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(8)
		}
		if err := os.WriteFile(*ready, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(9)
		}
	}
	if err := WriteReply(os.Stdout, r); err != nil {
		os.Exit(5)
	}
	if *mode == "reply-hang" {
		time.Sleep(time.Hour)
	}
	if *mode == "reply-fail" {
		os.Exit(6)
	}
	if *mode == "trailing" {
		fmt.Fprint(os.Stdout, "garbage")
	}
	os.Exit(0)
}

func processForTest(t *testing.T, mode string) *Processes {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	p, err := NewProcesses(exe, []string{"-test.run=^TestProcessChild$", "--", "--mode", mode}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}

func TestProcessOutcomes(t *testing.T) {
	for _, mode := range []string{"success", "error", "large", "early", "panic", "abort", "malformed", "truncated", "oversize", "wrong-id", "reply-hang", "reply-fail", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			p := processForTest(t, mode)
			r, err := p.Run(Job{RequestID: [32]byte{1}, Binary: make([]byte, 1<<20)})
			if mode == "success" || mode == "error" || mode == "large" {
				require.NoError(t, err)
				require.NoError(t, r.Validate([32]byte{1}))
			} else {
				require.Error(t, err)
			}
			require.Empty(t, p.PIDs())
		})
	}
}

func TestCrashDoesNotAffectOtherWorkers(t *testing.T) {
	good := processForTest(t, "slow")
	bad := processForTest(t, "panic")
	result := make(chan error, 1)
	go func() { _, err := good.Run(Job{}); result <- err }()
	_, err := bad.Run(Job{})
	require.Error(t, err)
	require.NoError(t, <-result)
	_, err = good.Run(Job{})
	require.NoError(t, err)
}

func TestCloseReapsWorker(t *testing.T) {
	p := processForTest(t, "hang")
	result := make(chan error, 1)
	go func() { _, err := p.Run(Job{}); result <- err }()
	require.Eventually(t, func() bool { return len(p.PIDs()) == 1 }, 5*time.Second, time.Millisecond)
	pid := p.PIDs()[0]
	require.NoError(t, p.Close())
	require.Error(t, <-result)
	require.Empty(t, p.PIDs())
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH)
	_, err := p.Run(Job{})
	require.Error(t, err)
}

func TestLaunchFailure(t *testing.T) {
	p := processForTest(t, "success")
	p.path = "/nonexistent-worker"
	_, err := p.Run(Job{})
	require.ErrorContains(t, err, "starting worker")
	require.Empty(t, p.PIDs())
}

func TestCloseRacingWithLaunch(t *testing.T) {
	for range 20 {
		p := processForTest(t, "blocked-input")
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				_, err := p.Run(Job{Binary: make([]byte, 1<<20)})
				assert.Error(t, err)
			})
		}
		require.NoError(t, p.Close())
		wg.Wait()
		require.Empty(t, p.PIDs())
	}
}

func TestCloseUnblocksInputWriter(t *testing.T) {
	p := processForTest(t, "blocked-input")
	result := make(chan error, 1)
	go func() { _, err := p.Run(Job{Binary: make([]byte, 1<<20)}); result <- err }()
	require.Eventually(t, func() bool { return len(p.PIDs()) == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, p.Close())
	require.Error(t, <-result)
	require.Empty(t, p.PIDs())
}

func TestRunsCloseOwnedDescriptors(t *testing.T) {
	p := processForTest(t, "success")
	_, err := p.Run(Job{})
	require.NoError(t, err)
	before, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	for range 3 {
		_, err = p.Run(Job{})
		require.NoError(t, err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	require.LessOrEqual(t, len(after), len(before))
}

func TestDescendantChild(t *testing.T) {
	if slices.Contains(os.Args, "--") {
		time.Sleep(time.Hour)
	}
}

func TestCoordinatorChild(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	p := processForTest(t, "hang")
	p.args = append(p.args, "--ready-file", os.Args[i+1])
	_, _ = p.Run(Job{})
}

func TestOrphanCleanup(t *testing.T) {
	// Adopt the test's orphaned children so the assertions can reap them rather
	// than depending on the environment's PID 1 to collect zombies promptly.
	require.NoError(t, unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0))
	t.Cleanup(func() { require.NoError(t, unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)) })
	readPID := func(t *testing.T, path string) int {
		var pid int
		require.Eventually(t, func() bool {
			data, _ := os.ReadFile(path)
			pid, _ = strconv.Atoi(string(data))
			return pid > 0
		}, 5*time.Second, time.Millisecond)
		return pid
	}
	assertKilled := func(t *testing.T, pid int) {
		var status syscall.WaitStatus
		var reaped bool
		t.Cleanup(func() {
			if !reaped {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				_, _ = syscall.Wait4(pid, nil, 0, nil)
			}
		})
		require.Eventually(t, func() bool {
			got, _ := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			reaped = got == pid
			return reaped
		}, 5*time.Second, time.Millisecond)
		require.True(t, status.Signaled())
		require.Equal(t, syscall.SIGKILL, status.Signal())
	}
	t.Run("coordinator death after stdin EOF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ready")
		exe, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.Command(exe, "-test.run=^TestCoordinatorChild$", "--", path)
		require.NoError(t, cmd.Start())
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		pid := readPID(t, path)
		require.NoError(t, cmd.Process.Kill())
		require.Error(t, cmd.Wait())
		assertKilled(t, pid)
	})
	t.Run("descendant retains stdout after worker exit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ready")
		p := processForTest(t, "descendant")
		p.args = append(p.args, "--ready-file", path)
		_, err := p.Run(Job{})
		require.NoError(t, err)
		assertKilled(t, readPID(t, path))
	})
}
