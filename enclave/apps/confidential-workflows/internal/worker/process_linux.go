package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"golang.org/x/sys/unix"
)

const exitGrace = 2 * time.Second
const diagnosticBytes = 64 << 10

// Processes supervises one fresh child per Run. It never retries an execution.
type Processes struct {
	path   string
	args   []string
	env    []string
	keys   keychain.Keychain
	logger logger.Logger
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active map[*exec.Cmd]struct{}
	wg     sync.WaitGroup
}

func NewProcesses(path string, args, environment []string, keys keychain.Keychain, lggr logger.Logger) (*Processes, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("worker path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("worker executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("worker is not executable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Processes{path: path, args: append([]string(nil), args...), env: append([]string(nil), environment...), keys: keys, logger: lggr,
		ctx: ctx, cancel: cancel, active: make(map[*exec.Cmd]struct{})}, nil
}

func (p *Processes) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

func (p *Processes) PIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make([]int, 0, len(p.active))
	for cmd := range p.active {
		ids = append(ids, cmd.Process.Pid)
	}
	return ids
}

func (p *Processes) Run(job Job) (Reply, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return Reply{}, errors.New("worker supervisor is closed")
	}
	p.wg.Add(1)
	p.mu.Unlock()
	defer p.wg.Done()
	if job.Gateway.URL != "" {
		if p.keys == nil {
			job.KeyError = "worker keychain is unavailable"
		} else {
			var err error
			job.Key, err = keychain.SnapshotForRequest(p.keys, job.RequestID)
			if err != nil {
				job.KeyError = err.Error()
			}
		}
	}
	job.Version = Version
	data, err := json.Marshal(job)
	if err != nil {
		return Reply{}, errors.New("encoding worker job")
	}

	// Linux ties Pdeathsig to the spawning thread, not the Go process. Keep that
	// thread alive until reaping so Go's thread retirement cannot kill a worker.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	args := append(append([]string(nil), p.args...), "--job-bytes", strconv.Itoa(len(data)), "--parent-pid", strconv.Itoa(os.Getpid()))
	cmd := exec.CommandContext(ctx, p.path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "GOTRACEBACK=single"}
	cmd.Env = append(cmd.Env, p.env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	var groupMu sync.Mutex
	var reaped bool
	killGroup := func() error {
		groupMu.Lock()
		defer groupMu.Unlock()
		if reaped {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = killGroup
	inR, inW, err := os.Pipe()
	if err != nil {
		return Reply{}, err
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		return Reply{}, err
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		return Reply{}, err
	}
	defer errR.Close()
	defer errW.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	if err = cmd.Start(); err != nil {
		return Reply{}, fmt.Errorf("starting worker: %w", err)
	}
	p.mu.Lock()
	p.active[cmd] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.active, cmd); p.mu.Unlock() }()
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()

	type completion struct {
		kind string
		err  error
	}
	done := make(chan completion, 5)
	var reply Reply
	var tail diagnosticTail
	start := time.Now()
	go func() { _, e := inW.Write(data); _ = inW.Close(); done <- completion{"input", e} }()
	go func() {
		e := Decode(outR, MaxReplyBytes, &reply, func() { done <- completion{kind: "frame"} })
		if e == nil {
			e = reply.Validate(job.RequestID)
		}
		done <- completion{"output", e}
	}()
	go func() { _, e := io.Copy(&tail, errR); done <- completion{"stderr", e} }()
	go func() {
		// Keep the exited leader waitable until group cleanup, preventing its
		// PID from being reused as another execution's process group.
		var info unix.Siginfo
		var err error
		for {
			err = unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if !errors.Is(err, syscall.EINTR) {
				break
			}
		}
		groupMu.Lock()
		if err == nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		reaped = true
		groupMu.Unlock()
		done <- completion{"exit", errors.Join(err, cmd.Wait())}
	}()

	var failure error
	var timer *time.Timer
	var timeout <-chan time.Time
	startCleanup := func() {
		if timer == nil {
			timer = time.NewTimer(exitGrace)
			timeout = timer.C
		}
	}
	stop := func() {
		cancel()
		_ = killGroup()
		_ = inW.Close()
		_ = outR.Close()
		_ = errR.Close()
	}
	finished := 0
	shutdown := p.ctx.Done()
	for finished < 4 {
		select {
		case c := <-done:
			if c.kind == "frame" {
				startCleanup()
				continue
			}
			finished++
			if c.kind == "exit" {
				startCleanup()
			}
			if c.err != nil && failure == nil {
				failure = fmt.Errorf("worker %s: %w", c.kind, c.err)
				stop()
			}
		case <-timeout:
			if failure == nil {
				failure = errors.New("worker did not complete exit/pipe cleanup")
			}
			timeout = nil
			stop()
		case <-shutdown:
			if failure == nil {
				failure = errors.New("worker supervisor shut down")
			}
			shutdown = nil
			stop()
		}
	}
	if timer != nil {
		timer.Stop()
	}
	if p.logger != nil {
		var peakRSS int64
		if cmd.ProcessState != nil {
			if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
				peakRSS = usage.Maxrss
			}
		}
		p.logger.Infow("worker completed", "requestID", fmt.Sprintf("%x", job.RequestID), "pid", cmd.Process.Pid,
			"elapsed", time.Since(start), "exit", cmd.ProcessState.String(), "error", failure,
			"peakRSSKB", peakRSS,
			"diagnosticsTruncated", tail.truncated, "diagnostics", string(tail.data))
	}
	if failure != nil {
		return Reply{}, failure
	}
	return reply, nil
}

type diagnosticTail struct {
	data      []byte
	truncated bool
}

func (t *diagnosticTail) Write(b []byte) (int, error) {
	n := len(b)
	if len(t.data)+n > diagnosticBytes {
		t.truncated = true
		if n >= diagnosticBytes {
			t.data = append(t.data[:0], b[n-diagnosticBytes:]...)
			return n, nil
		}
		t.data = append(t.data[:0], t.data[len(t.data)+n-diagnosticBytes:]...)
	}
	t.data = append(t.data, b...)
	return n, nil
}
