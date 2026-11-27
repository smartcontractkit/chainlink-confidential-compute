package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func eventLogs(logs *observer.ObservedLogs, event string) []map[string]any {
	var out []map[string]any
	for _, entry := range logs.All() {
		fields := entry.ContextMap()
		if fields["event"] == event {
			out = append(out, fields)
		}
	}
	return out
}

func writeJSONLine(t *testing.T, w io.Writer, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	_, err = w.Write(append(data, '\n'))
	require.NoError(t, err)
}

func TestCrashLiveStreamIsLogged(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleCrashStream(server, lggr, t.TempDir())
	}()

	writeJSONLine(t, client, types.CrashStreamHeader{Kind: types.CrashStreamLive, BootID: "boot1", App: "enclave-app"})
	writeJSONLine(t, client, types.CrashLiveMessage{Stream: "trace", UnixNano: 1, Lines: []string{"a", "b"}})
	writeJSONLine(t, client, types.CrashLiveMessage{Stream: "gocrash", UnixNano: 2, Lines: []string{"fatal error: boom"}})
	require.NoError(t, client.Close())
	<-done

	live := eventLogs(logs, "ENCLAVE_LIVE")
	require.Len(t, live, 2)
	require.Equal(t, "trace", live[0]["stream"])
	require.Equal(t, "a\nb", live[0]["lines"])
	require.Equal(t, "boot1", live[0]["bootID"])
	require.Equal(t, "fatal error: boom", live[1]["lines"])
	require.Equal(t, zapcore.ErrorLevel, logs.FilterField(zapcore.Field{Key: "stream", Type: zapcore.StringType, String: "gocrash"}).All()[0].Level)
}

func TestCrashReportIsStoredLoggedAndAcknowledged(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	dumpDir := t.TempDir()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleCrashStream(server, lggr, dumpDir)
	}()

	report := types.CrashReport{BootID: "boot2", App: "enclave-app", PID: 42, ExitCode: 134, Status: "signal: aborted (core dumped)", Signal: "aborted", CoreDumped: true,
		OOMKilled: true, OOMKills: 1, KernelOOMLines: []string{"Out of memory: Killed process 42 (enclave-app)"}}
	summary, err := json.Marshal(report)
	require.NoError(t, err)
	traceback := strings.Repeat("goroutine 1 [running]:\nmain.main()\n", 600) // several log chunks
	// Cores arrive already gzip-compressed by the supervisor.
	core := bytes.Repeat([]byte{0, 1, 2, 3}, 300_000)
	var compressedCore bytes.Buffer
	gz := gzip.NewWriter(&compressedCore)
	_, err = gz.Write(core)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{types.CrashReportFile, summary},
		{"go-crash.txt", []byte(traceback)},
		{"proc-last/maps.txt", []byte("00400000-00401000 r-xp\n")},
		{"../../escape.txt", []byte("contained")},
		{"app/heap-1.pprof", []byte{0x1f, 0x8b, 0x00, 0xff}},
		{"core/core.enclave-app.42.gz", compressedCore.Bytes()},
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data))}))
		_, err := tw.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	go func() {
		writeJSONLine(t, client, types.CrashStreamHeader{Kind: types.CrashStreamReport, BootID: "boot2", App: "enclave-app"})
		_, _ = client.Write(archive.Bytes())
	}()

	ack := make([]byte, len(types.CrashReportAck))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(client, ack)
	require.NoError(t, err)
	require.Equal(t, types.CrashReportAck, string(ack))
	require.NoError(t, client.Close())
	<-done

	dirs, err := os.ReadDir(dumpDir)
	require.NoError(t, err)
	require.Len(t, dirs, 1)
	require.True(t, strings.HasSuffix(dirs[0].Name(), "-boot2"))
	dir := filepath.Join(dumpDir, dirs[0].Name())

	stored, err := os.ReadFile(filepath.Join(dir, "go-crash.txt"))
	require.NoError(t, err)
	require.Equal(t, traceback, string(stored))
	require.FileExists(t, filepath.Join(dir, "proc-last", "maps.txt"))
	// A hostile entry name stays inside the dump directory.
	require.FileExists(t, filepath.Join(dir, "escape.txt"))
	require.NoFileExists(t, filepath.Join(dumpDir, "escape.txt"))

	coreFile, err := os.Open(filepath.Join(dir, "core", "core.enclave-app.42.gz"))
	require.NoError(t, err)
	defer coreFile.Close() //nolint:errcheck // test
	coreReader, err := gzip.NewReader(coreFile)
	require.NoError(t, err)
	storedCore, err := io.ReadAll(coreReader)
	require.NoError(t, err)
	require.Equal(t, core, storedCore)

	exit := eventLogs(logs, "ENCLAVE_APP_EXIT")
	require.Len(t, exit, 1)
	require.EqualValues(t, 134, exit[0]["exitCode"])
	require.Equal(t, "aborted", exit[0]["signal"])
	require.Equal(t, true, exit[0]["coreDumped"])
	require.Equal(t, true, exit[0]["oomKilled"])
	require.Contains(t, exit[0]["kernelOOMLines"], "Killed process 42")

	// The traceback is logged whole, in order, across several chunks; the core
	// is recorded but never logged.
	var logged strings.Builder
	var sawCore bool
	for _, fields := range eventLogs(logs, "ENCLAVE_CRASH_ARTIFACT") {
		switch fields["name"] {
		case "go-crash.txt":
			logged.WriteString(fields["data"].(string))
		case "app/heap-1.pprof":
			// A binary artifact is stored and summarised, not logged.
			require.NotContains(t, fields, "data")
			require.FileExists(t, filepath.Join(dir, "app", "heap-1.pprof"))
		case "core/core.enclave-app.42.gz":
			sawCore = true
			require.NotContains(t, fields, "data")
			require.EqualValues(t, compressedCore.Len(), fields["bytes"])
		}
	}
	require.Equal(t, traceback, logged.String())
	require.True(t, sawCore)
	require.Len(t, eventLogs(logs, "ENCLAVE_CRASH_REPORT_DONE"), 1)
}

func TestCrashReportWithoutDumpDirStillLogsAndAcks(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	// A file where the dump directory should be: nothing can be stored.
	blocked := filepath.Join(t.TempDir(), "blocked")
	require.NoError(t, os.WriteFile(blocked, nil, 0o600))

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleCrashStream(server, lggr, blocked)
	}()

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "go-crash.txt", Mode: 0o600, Size: 5}))
	_, err := tw.Write([]byte("boom\n"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	go func() {
		writeJSONLine(t, client, types.CrashStreamHeader{Kind: types.CrashStreamReport, BootID: "boot3"})
		_, _ = client.Write(archive.Bytes())
	}()
	ack := make([]byte, len(types.CrashReportAck))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(client, ack)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	<-done

	artifacts := eventLogs(logs, "ENCLAVE_CRASH_ARTIFACT")
	require.Len(t, artifacts, 1)
	require.Equal(t, "boom\n", artifacts[0]["data"])
	require.Equal(t, "", artifacts[0]["stored"])
}

func TestChunkTextBreaksAtLines(t *testing.T) {
	require.Empty(t, chunkText("", 10))
	require.Equal(t, []string{"ab\n", "cd\n", "ef"}, chunkText("ab\ncd\nef", 4))
	require.Equal(t, []string{"abcd", "efgh", "i"}, chunkText("abcdefghi", 4))
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	buf := &tailBuffer{max: 4}
	_, _ = buf.Write([]byte("abc"))
	_, _ = buf.Write([]byte("defg"))
	require.Equal(t, "defg", string(buf.Bytes()))
	require.EqualValues(t, 3, buf.dropped)
}

// TestSupervisorToHostEndToEnd builds the real enclave supervisor, lets it
// supervise a process that dies of a segmentation fault, and checks that this
// host's listener receives the live stream and the report over the (fake,
// TCP-backed) vsock channel both sides use.
func TestSupervisorToHostEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the supervisor binary")
	}
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	t.Setenv(types.EnvEnclaveCID, "47")

	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	dumpDir := t.TempDir()
	listener, err := vsock.ListenAt(vsock.CIDAny, types.CrashReportPort, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = serveCrashStreams(listener, lggr, dumpDir) }()

	supervisor := filepath.Join(t.TempDir(), "enclave-supervisor")
	build := exec.Command("go", "build", "-o", supervisor, "./enclave/nitro/supervisor/")
	build.Dir = filepath.Join("..", "..", "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "building the supervisor: %s", out)

	cmd := exec.Command(supervisor, "/bin/sh", "-c", "echo about to fault >&2; sleep 0.4; kill -SEGV $$")
	cmd.Env = append(os.Environ(),
		"ENCLAVE_CRASH_DIR="+t.TempDir(),
		"ENCLAVE_CRASH_CONSOLE_DRAIN=10ms",
		"ENCLAVE_CRASH_SAMPLE_INTERVAL=20ms",
	)
	console, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "supervisor output: %s", console)
	require.Equal(t, 128+11, exitErr.ExitCode(), "the supervisor exits with the app's status: %s", console)
	require.Contains(t, string(console), "about to fault", "the app's stderr is passed through")
	require.Contains(t, string(console), "ENCLAVE APP EXIT")
	require.Contains(t, string(console), "crash report delivered")

	require.Eventually(t, func() bool {
		return len(eventLogs(logs, "ENCLAVE_CRASH_REPORT_DONE")) == 1
	}, 10*time.Second, 20*time.Millisecond)

	exit := eventLogs(logs, "ENCLAVE_APP_EXIT")
	require.Len(t, exit, 1)
	require.EqualValues(t, 139, exit[0]["exitCode"])
	require.Equal(t, "segmentation fault", exit[0]["signal"])
	require.Equal(t, "sh", exit[0]["app"])
	require.Equal(t, false, exit[0]["oomKilled"])

	require.Len(t, eventLogs(logs, "ENCLAVE_LIVE_CONNECTED"), 1)
	var notes strings.Builder
	for _, fields := range eventLogs(logs, "ENCLAVE_LIVE") {
		if fields["stream"] == "note" {
			notes.WriteString(fields["lines"].(string) + "\n")
		}
	}
	require.Contains(t, notes.String(), "enclave app started")
	require.Contains(t, notes.String(), "enclave app exited")

	dirs, err := os.ReadDir(dumpDir)
	require.NoError(t, err)
	require.Len(t, dirs, 1)
	stored := filepath.Join(dumpDir, dirs[0].Name())
	summary, err := os.ReadFile(filepath.Join(stored, types.CrashReportFile))
	require.NoError(t, err)
	var report types.CrashReport
	require.NoError(t, json.Unmarshal(summary, &report))
	require.Equal(t, 139, report.ExitCode)
	require.Contains(t, report.Files, "samples.txt")
	require.FileExists(t, filepath.Join(stored, "samples.txt"))
	require.FileExists(t, filepath.Join(stored, "buildinfo.txt"))
}
