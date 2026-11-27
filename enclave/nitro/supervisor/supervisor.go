package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// config holds the supervisor's tunables. Each has an environment override so
// a rebuilt image can change it without a code change.
type config struct {
	// crashDir receives the app's trace ring, fatal output and core files.
	crashDir string
	// reportTimeout bounds the whole post-mortem upload, core included. It has
	// to stay under the time the host container survives without its enclave
	// (its liveness probe restarts it after about three minutes).
	reportTimeout time.Duration
	// consoleDrain is how long the VM is held open after the upload so the
	// serial console reaches the reader on the host.
	consoleDrain time.Duration
	// sampleEvery is the /proc sampling period.
	sampleEvery time.Duration
	// dialTimeout bounds one connection attempt to the host.
	dialTimeout time.Duration
	// crashExitGrace is how long an app that has started printing a fatal
	// error may take to exit (traceback, then core dump) before it is killed.
	crashExitGrace time.Duration
	// systemSetup allows machine-wide changes: sysctls, a tmpfs mount, the
	// core limit and OOM scores. Only the enclave entrypoint turns it on, so
	// running the supervisor anywhere else leaves the machine alone.
	systemSetup bool
}

// EnvSystemSetup is set to "true" by the enclave image's start script.
const EnvSystemSetup = "ENCLAVE_CRASH_SYSTEM_SETUP"

func loadConfig() config {
	return config{
		crashDir:       envOr(crashdebug.EnvCrashDir, "/crash"),
		reportTimeout:  envDuration("ENCLAVE_CRASH_REPORT_TIMEOUT", 120*time.Second),
		consoleDrain:   envDuration("ENCLAVE_CRASH_CONSOLE_DRAIN", 5*time.Second),
		sampleEvery:    envDuration("ENCLAVE_CRASH_SAMPLE_INTERVAL", 200*time.Millisecond),
		dialTimeout:    3 * time.Second,
		crashExitGrace: envDuration("ENCLAVE_CRASH_EXIT_GRACE", 90*time.Second),
		systemSetup:    os.Getenv(EnvSystemSetup) == "true",
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil && d > 0 {
		return d
	}
	return fallback
}

// dialHost opens a connection to the host's crash listener. Indirected so
// tests can run without a vsock peer.
var dialHost = func() (net.Conn, error) {
	return vsock.Dial(types.ProxyParentCID, types.CrashReportPort, nil)
}

// dialHostTimeout bounds dialHost, which has no deadline of its own.
func dialHostTimeout(timeout time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dialHost()
		ch <- result{conn, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-timer.C:
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("dial timed out after %s", timeout)
	}
}

// notes collects one-line records of what the supervisor set up, found or
// failed at. They go to the console, the live stream and the report.
type notes struct {
	mu    sync.Mutex
	lines []string
	live  *liveStream
}

func (n *notes) addf(format string, args ...any) {
	line := time.Now().UTC().Format("15:04:05.000000 ") + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, "supervisor: "+line)
	n.mu.Lock()
	n.lines = append(n.lines, line)
	live := n.live
	n.mu.Unlock()
	if live != nil {
		live.send("note", line)
	}
}

func (n *notes) snapshot() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.lines...)
}

func newBootID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// childEnv is the app's environment: ours, plus the crash directory and the
// settings that make a dying runtime say as much as it can.
func childEnv(cfg config) []string {
	env := os.Environ()
	have := make(map[string]bool, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		have[key] = true
	}
	for _, kv := range [][2]string{
		{crashdebug.EnvCrashDir, cfg.crashDir},
		// All goroutines, runtime frames and registers, then SIGABRT for a core.
		{"GOTRACEBACK", "crash"},
		// Native backtrace when Rust code (wasmtime) panics...
		{"RUST_BACKTRACE", "full"},
		// ...but no backtrace capture on ordinary error paths, which would
		// change the timing of the code under investigation.
		{"RUST_LIB_BACKTRACE", "0"},
	} {
		if !have[kv[0]] {
			env = append(env, kv[0]+"="+kv[1])
		}
	}
	return env
}

// supervise runs app, observes it until it exits, reports, and returns the
// exit code the enclave init will take as the VM's.
func supervise(app string, args []string) int {
	cfg := loadConfig()
	bootID := newBootID()
	appName := filepath.Base(app)

	live := newLiveStream(cfg, types.CrashStreamHeader{Kind: types.CrashStreamLive, BootID: bootID, App: appName})
	n := &notes{live: live}
	go guarded(n, "live stream", live.run)
	n.addf("boot %s: supervising %s %q (go %s, %s/%s)", bootID, app, args, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	prepare(cfg, n)

	kmsg := newKmsgReader(live, n)
	go guarded(n, "kernel log reader", kmsg.run)

	cmd := exec.Command(app, args...)
	// Inherited, not piped: the app keeps writing straight to the enclave
	// console exactly as it does without a supervisor.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = childEnv(cfg)

	started := time.Now()
	if err := cmd.Start(); err != nil {
		n.addf("cannot start enclave app: %v", err)
		live.close(2 * time.Second)
		time.Sleep(cfg.consoleDrain)
		return 1
	}
	pid := cmd.Process.Pid
	n.addf("enclave app started, pid %d", pid)
	if cfg.systemSetup {
		adjustOOMScores(pid, n)
	}
	startUptime := uptimeSeconds()

	smp := newSampler(cfg, pid, live, n)
	smp.killApp = cmd.Process.Kill
	go guarded(n, "sampler", smp.run)

	var terminating atomic.Bool
	stopForwarding := forwardSignals(cmd, &terminating)
	waitErr := cmd.Wait()
	exited := time.Now()
	stopForwarding()

	// The app is gone, so the enclave is down until this process exits and the
	// VM restarts. Whatever happens below, do not hold it open past this.
	hardExit := time.AfterFunc(cfg.reportTimeout+45*time.Second, func() {
		fmt.Fprintln(os.Stderr, "supervisor: post-mortem overran its budget, exiting now")
		os.Exit(exitCodeOf(cmd.ProcessState))
	})
	defer hardExit.Stop()
	// The app's vCPUs are idle now; use them for the post-mortem.
	runtime.GOMAXPROCS(runtime.NumCPU())

	report := buildCrashReport(appName, args, cmd.Env, pid, started, exited, cmd.ProcessState, waitErr)
	report.BootID = bootID
	report.Terminated = terminating.Load()
	n.addf("enclave app exited after %.3fs: %s (exit code %d)", report.UptimeSeconds, report.Status, report.ExitCode)

	smp.stop()
	// The kernel logs an OOM kill or a fatal signal slightly after the wait
	// returns; give those lines time to arrive.
	time.Sleep(500 * time.Millisecond)

	if nanos, count, ok := smp.heartbeat(); ok && nanos > 0 {
		report.LastHeartbeatUnixNano = nanos
		report.HeartbeatCount = count
		report.HeartbeatAgeSeconds = exited.Sub(time.Unix(0, nanos)).Seconds()
	}

	// A bare SIGKILL says nothing; the kernel's own record says whether it was
	// the OOM killer.
	kmsg.flush()
	report.OOMKills = smp.oomKills()
	report.KernelOOMLines = tail(oomLines(kmsg.ring.snapshot(), startUptime), 60)
	report.OOMKilled = report.Signal == syscall.SIGKILL.String() && (report.OOMKills > 0 || len(report.KernelOOMLines) > 0)
	switch {
	case report.OOMKilled:
		n.addf("VERDICT: the kernel OOM killer killed the app (%d kill(s) this boot, peak rss %d MiB)", report.OOMKills, report.PeakRSSBytes>>20)
	case report.Signal == syscall.SIGKILL.String():
		n.addf("the app was killed by SIGKILL and the kernel recorded no OOM kill")
	}

	entries := collectArtifacts(cfg, app, smp, kmsg, n)
	printSummary(os.Stderr, report, smp)
	sendReport(cfg, &report, entries, n)

	live.close(3 * time.Second)
	fmt.Fprintf(os.Stderr, "supervisor: holding the VM for %s so the console drains\n", cfg.consoleDrain)
	time.Sleep(cfg.consoleDrain)
	return report.ExitCode
}

// exitCodeOf is the code the supervisor exits with for a given child state.
func exitCodeOf(state *os.ProcessState) int {
	if state == nil {
		return 1
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}

// guarded runs fn so that a bug in a collector cannot take the supervisor,
// and with it the enclave, down.
func guarded(n *notes, what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			n.addf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

// forwardSignals relays termination signals to the child and records having
// done so. It returns a function that stops forwarding.
func forwardSignals(cmd *exec.Cmd, terminating *atomic.Bool) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigCh:
				terminating.Store(true)
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

func buildCrashReport(app string, args, env []string, pid int, started, exited time.Time, state *os.ProcessState, waitErr error) types.CrashReport {
	report := types.CrashReport{
		App:             app,
		Args:            args,
		Env:             env,
		PID:             pid,
		StartedUnixNano: started.UnixNano(),
		ExitedUnixNano:  exited.UnixNano(),
		Exited:          exited.UTC().Format(time.RFC3339Nano),
		UptimeSeconds:   exited.Sub(started).Seconds(),
	}

	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		report.WaitError = waitErr.Error()
		report.ExitCode = 1
	}
	if state == nil {
		return report
	}

	report.Status = state.String()
	report.ExitCode = state.ExitCode()
	report.UserCPUSeconds = state.UserTime().Seconds()
	report.SystemCPUSeconds = state.SystemTime().Seconds()

	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		report.Signal = status.Signal().String()
		report.CoreDumped = status.CoreDump()
		report.ExitCode = 128 + int(status.Signal())
	}
	if rusage, ok := state.SysUsage().(*syscall.Rusage); ok && rusage != nil {
		report.PeakRSSBytes = peakRSSBytes(rusage)
		report.MinorFaults = int64(rusage.Minflt)
		report.MajorFaults = int64(rusage.Majflt)
		report.VoluntaryCtxSwitches = int64(rusage.Nvcsw)
		report.InvoluntaryCtxSwitch = int64(rusage.Nivcsw)
	}
	return report
}

// peakRSSBytes converts ru_maxrss, which is kilobytes on Linux and bytes on
// Darwin.
func peakRSSBytes(rusage *syscall.Rusage) uint64 {
	if rusage.Maxrss <= 0 {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(rusage.Maxrss)
	}
	return uint64(rusage.Maxrss) * 1024
}
