package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
)

const childModeEnv = "SUPERVISOR_TEST_CHILD"

// TestMain doubles as the supervised app: re-executed with childModeEnv set,
// the test binary behaves like an enclave app that fails in the chosen way.
func TestMain(m *testing.M) {
	switch os.Getenv(childModeEnv) {
	case "":
		os.Exit(m.Run())
	case "panic":
		childInit()
		crashdebug.Tracef("exec start rid=abc")
		time.Sleep(400 * time.Millisecond)
		crashdebug.Tracef("about to die")
		go func() { panic("boom from a goroutine") }()
		time.Sleep(10 * time.Second)
	case "exit3":
		childInit()
		crashdebug.Tracef("leaving with status 3")
		os.Exit(3)
	case "memdump":
		// What an app under memory pressure leaves behind before the OOM
		// killer's SIGKILL: its watchdog's dumps, and nothing on stderr.
		childInit()
		dir := os.Getenv(crashdebug.EnvCrashDir)
		_ = os.WriteFile(filepath.Join(dir, crashdebug.GoroutineDumpPrefix+"01.txt"), []byte("memory watchdog #1\ngoroutine 7 [running]:\nwasm.compile()\n"), 0o600)
		_ = os.WriteFile(filepath.Join(dir, crashdebug.HeapProfilePrefix+"01.pprof"), []byte{0x1f, 0x8b, 0x08}, 0o600)
		time.Sleep(600 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(10 * time.Second)
	case "kill":
		childInit()
		crashdebug.Tracef("killing myself")
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}

func childInit() {
	crashdebug.Init(func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "child: "+format+"\n", args...)
	})
}

type receivedReport struct {
	header  types.CrashStreamHeader
	report  types.CrashReport
	entries map[string][]byte
}

// fakeHost stands in for the host's crash listener over in-memory pipes.
type fakeHost struct {
	mu      sync.Mutex
	live    []types.CrashLiveMessage
	reports []receivedReport
}

func (h *fakeHost) dial() (net.Conn, error) {
	client, server := net.Pipe()
	go h.serve(server)
	return client, nil
}

func (h *fakeHost) serve(conn net.Conn) {
	defer conn.Close() //nolint:errcheck // test
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var header types.CrashStreamHeader
	if json.Unmarshal(line, &header) != nil {
		return
	}
	switch header.Kind {
	case types.CrashStreamLive:
		dec := json.NewDecoder(br)
		for {
			var msg types.CrashLiveMessage
			if dec.Decode(&msg) != nil {
				return
			}
			h.mu.Lock()
			h.live = append(h.live, msg)
			h.mu.Unlock()
		}
	case types.CrashStreamReport:
		tr := tar.NewReader(br)
		got := receivedReport{header: header, entries: make(map[string][]byte)}
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			data, _ := io.ReadAll(tr)
			got.entries[hdr.Name] = data
		}
		_ = json.Unmarshal(got.entries[types.CrashReportFile], &got.report)
		h.mu.Lock()
		h.reports = append(h.reports, got)
		h.mu.Unlock()
		_, _ = io.WriteString(conn, types.CrashReportAck)
	}
}

func (h *fakeHost) liveLines(stream string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, msg := range h.live {
		if msg.Stream == stream {
			b.WriteString(strings.Join(msg.Lines, "\n"))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (h *fakeHost) onlyReport(t *testing.T) receivedReport {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	require.Len(t, h.reports, 1)
	return h.reports[0]
}

// runSupervised runs the test binary as a supervised app in the given mode.
func runSupervised(t *testing.T, mode string) (int, *fakeHost, string) {
	t.Helper()
	host := &fakeHost{}
	original := dialHost
	dialHost = host.dial
	t.Cleanup(func() { dialHost = original })

	dir := t.TempDir()
	t.Setenv(crashdebug.EnvCrashDir, dir)
	t.Setenv("ENCLAVE_CRASH_CONSOLE_DRAIN", "10ms")
	t.Setenv("ENCLAVE_CRASH_SAMPLE_INTERVAL", "20ms")
	t.Setenv(childModeEnv, mode)
	return supervise(os.Args[0], nil), host, dir
}

func TestSuperviseCapturesAGoroutinePanic(t *testing.T) {
	code, host, _ := runSupervised(t, "panic")
	require.Equal(t, 128+int(syscall.SIGABRT), code, "GOTRACEBACK=crash ends in SIGABRT")

	got := host.onlyReport(t)
	require.Equal(t, types.CrashStreamReport, got.header.Kind)
	require.Equal(t, code, got.report.ExitCode)
	require.NotEmpty(t, got.report.Signal)
	require.NotEmpty(t, got.report.Status)
	require.Greater(t, got.report.UptimeSeconds, 0.3)
	require.Positive(t, got.report.HeartbeatCount)
	require.NotEmpty(t, got.report.Notes)
	require.Contains(t, strings.Join(got.report.Env, "\n"), "GOTRACEBACK=crash")
	require.Contains(t, got.report.Files, crashdebug.GoCrashFile)

	// The runtime's own fatal output, with every goroutine, not just the one
	// that panicked.
	fatal := string(got.entries[crashdebug.GoCrashFile])
	require.Contains(t, fatal, "panic: boom from a goroutine")
	require.Contains(t, fatal, "supervisor.TestMain")
	require.Greater(t, strings.Count(fatal, "\ngoroutine "), 1)

	trace := string(got.entries["trace.txt"])
	require.Contains(t, trace, "exec start rid=abc")
	require.Contains(t, trace, "about to die")
	require.Less(t, strings.Index(trace, "exec start rid=abc"), strings.Index(trace, "about to die"))
	require.NotEmpty(t, got.entries["samples.txt"])
	require.Contains(t, string(got.entries["buildinfo.txt"]), "sha256:")

	// The same evidence also went out live, before the app was gone.
	require.Contains(t, host.liveLines("gocrash"), "panic: boom from a goroutine")
	require.Contains(t, host.liveLines("trace"), "about to die")
	require.Contains(t, host.liveLines("note"), "enclave app started")
	require.Contains(t, host.liveLines("note"), "fatal runtime output detected")
}

func TestSuperviseReportsAPlainExit(t *testing.T) {
	code, host, _ := runSupervised(t, "exit3")
	require.Equal(t, 3, code)
	got := host.onlyReport(t)
	require.Equal(t, 3, got.report.ExitCode)
	require.Empty(t, got.report.Signal)
	require.False(t, got.report.CoreDumped)
	require.Contains(t, string(got.entries["trace.txt"]), "leaving with status 3")
	require.NotContains(t, got.entries, crashdebug.GoCrashFile, "an os.Exit prints no fatal output")
}

func TestSuperviseReportsAKill(t *testing.T) {
	code, host, _ := runSupervised(t, "kill")
	require.Equal(t, 128+int(syscall.SIGKILL), code)
	got := host.onlyReport(t)
	require.Equal(t, "killed", got.report.Signal)
	// A SIGKILL leaves nothing behind except what was already in the ring.
	require.Contains(t, string(got.entries["trace.txt"]), "killing myself")
}

func TestSuperviseShipsTheAppsMemoryDumps(t *testing.T) {
	code, host, _ := runSupervised(t, "memdump")
	require.Equal(t, 128+int(syscall.SIGKILL), code)
	got := host.onlyReport(t)
	require.Equal(t, "killed", got.report.Signal)
	// No kernel log off Linux, so no OOM verdict here; the fields still travel.
	require.False(t, got.report.OOMKilled)
	require.Contains(t, strings.Join(got.report.Notes, "\n"), "recorded no OOM kill")

	require.Contains(t, string(got.entries["app/"+crashdebug.GoroutineDumpPrefix+"01.txt"]), "wasm.compile()")
	require.Equal(t, []byte{0x1f, 0x8b, 0x08}, got.entries["app/"+crashdebug.HeapProfilePrefix+"01.pprof"])
	// The stacks also went out live, while the app was still alive.
	require.Contains(t, host.liveLines("appdump"), "wasm.compile()")
	require.NotContains(t, got.entries, "app/"+crashdebug.TraceRingFile)
}

func TestMemoryWatchPressureLevelsAndSurge(t *testing.T) {
	const gib = uint64(1) << 20 // in kB
	now := time.Unix(1000, 0)
	var w memoryWatch

	require.Empty(t, w.check(now, 10*gib, 7*gib, 2*gib), "normal headroom")
	require.Contains(t, w.check(now, 10*gib, 2*gib, 7*gib), "under 25%")
	require.Empty(t, w.check(now, 10*gib, 2*gib, 7*gib), "a level reports once per descent")
	require.Contains(t, w.check(now, 10*gib, gib/4, 9*gib), "under 4%", "the deepest level reached is the one reported")
	require.Empty(t, w.check(now, 10*gib, 7*gib, 2*gib), "recovered")
	require.Contains(t, w.check(now, 10*gib, gib, 8*gib), "under 15%", "armed again after recovery")

	var s memoryWatch
	require.Empty(t, s.check(now, 100*gib, 90*gib, gib))
	require.Contains(t, s.check(now, 100*gib, 89*gib, 2*gib), "app rss grew 1024MiB")
	require.Empty(t, s.check(now.Add(time.Second), 100*gib, 88*gib, 3*gib), "rate limited")
	require.Empty(t, s.check(now, 0, 0, 5*gib), "no memory total, no verdict")
}

func TestOOMEvidenceParsers(t *testing.T) {
	kmsg := []string{
		"[   10.000000] <6> Run /init as init process",
		"[  812.100000] <4> enclave-app invoked oom-killer: gfp_mask=0x140cca, order=0, oom_score_adj=300",
		"[  812.100500] <6> [    11]     0    11  2600000  2400000 19500000        0           300 enclave-app",
		"[  812.101000] <3> Out of memory: Killed process 11 (enclave-app) total-vm:10400000kB, anon-rss:9600000kB",
		"[  812.150000] <6> oom_reaper: reaped process 11 (enclave-app)",
	}
	lines := oomLines(kmsg, 0)
	require.Len(t, lines, 3)
	require.Contains(t, lines[1], "Killed process 11")
	require.Empty(t, oomLines(kmsg[:1], 0))
	// A kill logged before the app started is someone else's.
	require.Empty(t, oomLines(kmsg, 900))
	require.Len(t, oomLines(kmsg, 812.1004), 2)
	at, ok := kmsgSeconds(kmsg[3])
	require.True(t, ok)
	require.InDelta(t, 812.101, at, 1e-9)
	_, ok = kmsgSeconds("[kmsg] records lost to ring overrun")
	require.False(t, ok)

	kills, ok := vmstatCounter("nr_free_pages 123\noom_kill 2\npgfault 99\n", "oom_kill")
	require.True(t, ok)
	require.EqualValues(t, 2, kills)
	_, ok = vmstatCounter("nr_free_pages 123\n", "oom_kill")
	require.False(t, ok)
}

func TestSummarizeMapsListsTheLargestWritableMappings(t *testing.T) {
	maps := strings.Join([]string{
		"00400000-00c00000 r-xp 00000000 00:02 100 /usr/bin/enclave-app",
		"c000000000-c040000000 rw-p 00000000 00:00 0 ",
		"7f0000000000-7f0100000000 ---p 00000000 00:00 0 ",
		"7f0100000000-7f0300000000 rw-p 00000000 00:00 0 ",
		"7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0 [stack]",
		"not a mapping line",
	}, "\n")
	lines := summarizeMaps(maps, 2)
	text := strings.Join(lines, "\n")
	require.Equal(t, "mappings=5 writable=3", lines[0])
	require.Contains(t, text, "total anon           9216MiB")
	require.Contains(t, text, "total anon-reserved  4096MiB")
	// Largest writable mapping first, and only the top two.
	require.Contains(t, lines[len(lines)-2], "7f0100000000-7f0300000000 rw-p 8192MiB")
	require.Contains(t, lines[len(lines)-1], "00c000000000-00c040000000 rw-p 1024MiB")
	require.NotContains(t, text, "7ffc00000000-7ffc00021000")
}

func TestSuperviseSurvivesAnUnreachableHost(t *testing.T) {
	original := dialHost
	dialHost = func() (net.Conn, error) { return nil, errors.New("no host") }
	t.Cleanup(func() { dialHost = original })
	t.Setenv(crashdebug.EnvCrashDir, t.TempDir())
	t.Setenv("ENCLAVE_CRASH_CONSOLE_DRAIN", "10ms")
	t.Setenv("ENCLAVE_CRASH_SAMPLE_INTERVAL", "20ms")
	t.Setenv(childModeEnv, "exit3")

	started := time.Now()
	require.Equal(t, 3, supervise(os.Args[0], nil))
	require.Less(t, time.Since(started), 30*time.Second)
}

func TestSuperviseFailsWhenTheAppCannotStart(t *testing.T) {
	host := &fakeHost{}
	original := dialHost
	dialHost = host.dial
	t.Cleanup(func() { dialHost = original })
	t.Setenv(crashdebug.EnvCrashDir, t.TempDir())
	t.Setenv("ENCLAVE_CRASH_CONSOLE_DRAIN", "10ms")
	require.Equal(t, 1, supervise(filepath.Join(t.TempDir(), "missing"), nil))
	require.Contains(t, host.liveLines("note"), "cannot start enclave app")
}

func TestChildEnvKeepsExistingSettings(t *testing.T) {
	t.Setenv("GOTRACEBACK", "single")
	env := strings.Join(childEnv(config{crashDir: "/crash"}), "\n")
	require.Contains(t, env, "GOTRACEBACK=single")
	require.NotContains(t, env, "GOTRACEBACK=crash")
	require.Contains(t, env, crashdebug.EnvCrashDir+"=/crash")
	require.Contains(t, env, "RUST_BACKTRACE=full")
	require.Contains(t, env, "RUST_LIB_BACKTRACE=0")
}

func TestParseStat(t *testing.T) {
	// The command name may itself contain spaces and parentheses.
	line := "1234 (enclave (app) x) R 1 1234 1234 0 -1 4194560 100 0 7 0 250 50 0 0 20 0 42 0 100 2147483648 5000 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
	comm, f, ok := parseStat(line)
	require.True(t, ok)
	require.Equal(t, "enclave (app) x", comm)
	require.Equal(t, "R", f[0])
	require.EqualValues(t, 100, statField(f, statMinFlt))
	require.EqualValues(t, 7, statField(f, statMajFlt))
	require.EqualValues(t, 250, statField(f, statUTime))
	require.EqualValues(t, 50, statField(f, statSTime))
	require.EqualValues(t, 42, statField(f, statNumThreads))
	require.EqualValues(t, 2147483648, statField(f, statVSize))
	require.EqualValues(t, 5000, statField(f, statRSSPages))
	require.EqualValues(t, 3, statField(f, statProcessor))
	require.EqualValues(t, 0, statField(f, 99))

	_, _, ok = parseStat("garbage")
	require.False(t, ok)
}

func TestFormatKmsg(t *testing.T) {
	line, ok := formatKmsg("3,1234,98765432,-;Out of memory: Killed process 11 (enclave-app)\n SUBSYSTEM=x\n")
	require.True(t, ok)
	require.Equal(t, "[   98.765432] <3> Out of memory: Killed process 11 (enclave-app)", line)
	_, ok = formatKmsg("not a record")
	require.False(t, ok)
}

func TestProcParsers(t *testing.T) {
	mem := parseKeyedKB("MemTotal:       10229760 kB\nMemAvailable:    7654321 kB\nHugePages_Total:       0\nbogus line\n")
	require.EqualValues(t, 10229760, mem["MemTotal"])
	require.EqualValues(t, 7654321, mem["MemAvailable"])
	require.Equal(t, "9990MiB", mib(mem["MemTotal"]))

	require.Equal(t, "1.25", parsePressure("some avg10=1.25 avg60=0.50 avg300=0.10 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"))
	require.Equal(t, "-", parsePressure(""))
	require.Equal(t, "0.52", firstField("0.52 0.40 0.30 2/345 6789\n"))
}

func TestLineRingKeepsTheNewest(t *testing.T) {
	ring := newLineRing(3)
	require.Empty(t, ring.snapshot())
	for _, s := range []string{"a", "b"} {
		ring.add(s)
	}
	require.Equal(t, []string{"a", "b"}, ring.snapshot())
	for _, s := range []string{"c", "d", "e"} {
		ring.add(s)
	}
	require.Equal(t, []string{"c", "d", "e"}, ring.snapshot())
}

func TestLiveSendSplitsLargeBatches(t *testing.T) {
	live := newLiveStream(config{}, types.CrashStreamHeader{})
	lines := make([]string, 150)
	for i := range lines {
		lines[i] = strings.Repeat("x", 200)
	}
	live.send("trace", lines...)
	live.send("trace")

	var total int
	for len(live.queue) > 0 {
		msg := <-live.queue
		size := 0
		for _, line := range msg.Lines {
			size += len(line)
		}
		require.LessOrEqual(t, len(msg.Lines), liveMaxLines)
		require.LessOrEqual(t, size, liveMaxBytes)
		total += len(msg.Lines)
	}
	require.Equal(t, 150, total)

	// One oversized line still goes out, alone.
	live.send("gocrash", strings.Repeat("y", 3*liveMaxBytes))
	require.Len(t, (<-live.queue).Lines, 1)
}

func TestForwardCrashOutputHoldsBackPartialLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, crashdebug.GoCrashFile)
	live := newLiveStream(config{}, types.CrashStreamHeader{})
	smp := newSampler(config{crashDir: dir, sampleEvery: time.Second}, os.Getpid(), live, &notes{})

	require.False(t, smp.forwardCrashOutput(false), "no file yet")
	require.NoError(t, os.WriteFile(path, []byte("fatal error: one\ngoroutine 1 [run"), 0o600))
	require.True(t, smp.forwardCrashOutput(false))
	require.Equal(t, []string{"fatal error: one"}, (<-live.queue).Lines)
	require.False(t, smp.forwardCrashOutput(false), "the partial line waits")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString("ning]:\nmain.main()")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.True(t, smp.forwardCrashOutput(false))
	require.Equal(t, []string{"goroutine 1 [running]:"}, (<-live.queue).Lines)
	require.True(t, smp.forwardCrashOutput(true), "the final flush takes the remainder")
	require.Equal(t, []string{"main.main()"}, (<-live.queue).Lines)
	require.False(t, smp.forwardCrashOutput(true))
}

func readArchive(t *testing.T, r io.Reader) (map[string][]byte, []string) {
	t.Helper()
	tr := tar.NewReader(r)
	got := make(map[string][]byte)
	var order []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got, order
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		got[hdr.Name] = data
		order = append(order, hdr.Name)
	}
}

func TestWriteArchiveCompressesCoresAndPadsShortFiles(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "heap-01.pprof")
	require.NoError(t, os.WriteFile(short, []byte("abc"), 0o600))
	// A "core" with structure, zeros and an odd length, so the ranges differ.
	core := append(bytes.Repeat([]byte("core data "), 150_000), make([]byte, 700_001)...)
	corePath := filepath.Join(dir, "core.enclave-app.11.sig6.1")
	require.NoError(t, os.WriteFile(corePath, core, 0o600))

	entries := []entry{
		{name: "trace.txt", data: []byte("hello\n"), size: 6},
		{name: "app/heap-01.pprof", path: short, size: 10},
		{name: "core/core.enclave-app.11.sig6.1", path: corePath, compress: true, size: int64(len(core))},
		{name: "core/core.gone", path: corePath + ".missing", compress: true, size: 5},
	}

	var buf bytes.Buffer
	_, err := writeArchive(&buf, types.CrashReport{App: "x", ExitCode: 2}, entries, dir, time.Now().Add(time.Minute), &notes{})
	require.NoError(t, err)

	got, order := readArchive(t, &buf)
	require.Equal(t, []string{types.CrashReportFile, "trace.txt", "app/heap-01.pprof",
		"core/core.enclave-app.11.sig6.1.gz", "core/core.gone.failed.txt"}, order)
	require.Equal(t, "hello\n", string(got["trace.txt"]))
	require.Equal(t, append([]byte("abc"), make([]byte, 7)...), got["app/heap-01.pprof"])

	// The parts, concatenated, gunzip back to the original core.
	compressed := got["core/core.enclave-app.11.sig6.1.gz"]
	require.Less(t, len(compressed), len(core)/10)
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	restored, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.Equal(t, core, restored)

	// The scratch parts are gone.
	left, err := filepath.Glob(filepath.Join(dir, ".*.part*.gz"))
	require.NoError(t, err)
	require.Empty(t, left)

	var report types.CrashReport
	require.NoError(t, json.Unmarshal(got[types.CrashReportFile], &report))
	require.Equal(t, 2, report.ExitCode)
}

func TestCompressParallelGivesUpAtTheDeadline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.x")
	require.NoError(t, os.WriteFile(path, make([]byte, 1<<20), 0o600))
	_, _, err := compressParallel(path, dir, 2, time.Now().Add(-time.Second))
	require.ErrorContains(t, err, "ran out of time")
}
