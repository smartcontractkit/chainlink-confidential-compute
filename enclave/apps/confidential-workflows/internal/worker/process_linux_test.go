package worker

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	ready := fs.String("ready-file", "", "")
	_ = fs.Parse(os.Args[i+1:])
	if *mode == "early" {
		os.Exit(0)
	}
	if *mode == "blocked-input" {
		_ = os.WriteFile(*ready, []byte(strconv.Itoa(os.Getpid())), 0600)
		time.Sleep(time.Hour)
	}
	var job Job
	data, err := io.ReadAll(os.Stdin)
	if err != nil || json.Unmarshal(data, &job) != nil {
		os.Exit(4)
	}
	if *ready != "" {
		if err := os.WriteFile(*ready, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(7)
		}
	}
	r := successReply("hello")
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
		_, _ = fmt.Fprint(os.Stdout, "not JSON")
		os.Exit(0)
	case "garbage-hang":
		_, _ = fmt.Fprint(os.Stdout, "not JSON")
		time.Sleep(time.Hour)
	case "truncated":
		_, _ = fmt.Fprint(os.Stdout, `{"Result":`)
		os.Exit(0)
	case "oversize", "oversize-hang":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat(" ", MaxReplyBytes+1))
		if *mode == "oversize-hang" {
			time.Sleep(time.Hour)
		}
		os.Exit(0)
	case "empty":
		r = Reply{}
	case "both":
		r.Error = &types.ExecuteError{Error: "contradictory", Code: 500}
	case "error":
		r.Result, r.Error = nil, &types.ExecuteError{Error: types.ErrWasmExecutionTimeout, Code: 504}
	case "large":
		r = successReply(strings.Repeat("x", 8<<20))
	case "slow":
		time.Sleep(200 * time.Millisecond)
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestDescendantChild$", "--")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(8)
		}
		if err := os.WriteFile(*ready, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(9)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(5)
	}
	if *mode == "reply-hang" {
		time.Sleep(time.Hour)
	}
	if *mode == "reply-fail" {
		os.Exit(6)
	}
	if *mode == "trailing" {
		_, _ = fmt.Fprint(os.Stdout, "garbage")
	}
	os.Exit(0)
}

func processForTest(t *testing.T, mode string) *Processes {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	p, err := NewProcesses(exe, []string{"-test.run=^TestProcessChild$", "--", "--mode", mode}, nil, nil, nil)
	require.NoError(t, err)
	return p
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(path)
		pid, _ = strconv.Atoi(string(data))
		return pid > 0
	}, 5*time.Second, time.Millisecond)
	return pid
}

func TestProcessOutcomes(t *testing.T) {
	for _, mode := range []string{"success", "error", "large", "early", "panic", "abort", "malformed", "garbage-hang", "truncated", "oversize", "oversize-hang", "empty", "both", "reply-hang", "reply-fail", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			p := processForTest(t, mode)
			start := time.Now()
			r, err := p.Run(t.Context(), Job{RequestID: [32]byte{1}, Binary: make([]byte, 1<<20)})
			require.Less(t, time.Since(start), 8*time.Second)
			if mode == "success" || mode == "error" || mode == "large" {
				require.NoError(t, err)
				require.True(t, r.Result != nil || r.Error != nil)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCrashDoesNotAffectOtherWorkers(t *testing.T) {
	good := processForTest(t, "slow")
	bad := processForTest(t, "panic")
	result := make(chan error, 1)
	go func() { _, err := good.Run(t.Context(), Job{}); result <- err }()
	_, err := bad.Run(t.Context(), Job{})
	require.Error(t, err)
	require.NoError(t, <-result)
	_, err = good.Run(t.Context(), Job{})
	require.NoError(t, err)
}

func TestCancelReapsWorker(t *testing.T) {
	p := processForTest(t, "hang")
	path := filepath.Join(t.TempDir(), "ready")
	p.args = append(p.args, "--ready-file", path)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Job{}); result <- err }()
	pid := readPID(t, path)
	cancel()
	require.Error(t, <-result)
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH)
	_, err := p.Run(ctx, Job{})
	require.Error(t, err)
}

func TestLaunchFailure(t *testing.T) {
	p := processForTest(t, "success")
	p.path = "/nonexistent-worker"
	_, err := p.Run(t.Context(), Job{})
	require.ErrorContains(t, err, "no such file")
}

func TestCancelRacingWithLaunch(t *testing.T) {
	for range 20 {
		p := processForTest(t, "blocked-input")
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				_, err := p.Run(ctx, Job{Binary: make([]byte, 1<<20)})
				assert.Error(t, err)
			})
		}
		cancel()
		wg.Wait()
	}
}

func TestCancelUnblocksInputWriter(t *testing.T) {
	p := processForTest(t, "blocked-input")
	path := filepath.Join(t.TempDir(), "ready")
	p.args = append(p.args, "--ready-file", path)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Job{Binary: make([]byte, 1<<20)}); result <- err }()
	pid := readPID(t, path)
	cancel()
	require.Error(t, <-result)
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH)
}

func TestRunsCloseOwnedDescriptors(t *testing.T) {
	p := processForTest(t, "success")
	_, err := p.Run(t.Context(), Job{})
	require.NoError(t, err)
	before, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	for range 3 {
		_, err = p.Run(t.Context(), Job{})
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
	_, _ = p.Run(t.Context(), Job{})
}

func TestOrphanCleanup(t *testing.T) {
	// Adopt the test's orphaned children so the assertions can reap them rather
	// than depending on the environment's PID 1 to collect zombies promptly.
	require.NoError(t, unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0))
	t.Cleanup(func() { require.NoError(t, unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)) })
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
		start := time.Now()
		_, err := p.Run(t.Context(), Job{})
		require.ErrorIs(t, err, exec.ErrWaitDelay)
		require.Less(t, time.Since(start), 5*time.Second)
		pid := readPID(t, path)
		// V1 workers do not spawn subprocesses. Stray inherited pipes cannot
		// hold admission forever, but descendants are not supervised.
		require.NoError(t, syscall.Kill(pid, syscall.SIGKILL))
		assertKilled(t, pid)
	})
}
