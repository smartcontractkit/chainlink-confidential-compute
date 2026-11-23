package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// DEBUG BUILDS ONLY: everything the enclave supervisor sends is logged and
// stored in the clear.

// crashDumpDir is where report archives are unpacked. Mount a volume there to
// keep them across a container restart. Reads CRASH_DUMP_DIR.
var crashDumpDir = flag.String("crash-dump-dir", cmp.Or(os.Getenv("CRASH_DUMP_DIR"), "/tmp/enclave-crash"), "Directory enclave crash reports are unpacked into. Reads CRASH_DUMP_DIR.")

const (
	// crashLogChunkBytes keeps one logged chunk below the 16 KiB a container
	// runtime writes as a single log line, after JSON escaping.
	crashLogChunkBytes = 6000
	// crashLogEntryMaxBytes caps how much of one artifact is logged; the tail
	// is kept. The stored copy is always complete.
	crashLogEntryMaxBytes = 1 << 20

	crashHeaderTimeout = 30 * time.Second
	crashReportTimeout = 5 * time.Minute
	crashAckTimeout    = 5 * time.Second
	crashLineMaxBytes  = 4 << 20
)

// serveCrashStreams accepts supervisor connections until the listener closes.
func serveCrashStreams(listener net.Listener, lggr logger.Logger, dumpDir string) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleCrashStream(conn, lggr, dumpDir)
	}
}

func handleCrashStream(conn net.Conn, lggr logger.Logger, dumpDir string) {
	defer conn.Close() //nolint:errcheck // best-effort cleanup

	br := bufio.NewReaderSize(conn, 256<<10)
	_ = conn.SetReadDeadline(time.Now().Add(crashHeaderTimeout))
	line, err := readBoundedLine(br, crashLineMaxBytes)
	if err != nil {
		lggr.Errorw("enclave crash stream: no header", "error", err)
		return
	}
	var header types.CrashStreamHeader
	if err := json.Unmarshal(line, &header); err != nil {
		lggr.Errorw("enclave crash stream: bad header", "error", err)
		return
	}

	switch header.Kind {
	case types.CrashStreamLive:
		handleCrashLive(conn, br, header, lggr)
	case types.CrashStreamReport:
		handleCrashReport(conn, br, header, lggr, dumpDir)
	default:
		lggr.Errorw("enclave crash stream: unknown kind", "kind", header.Kind)
	}
}

// readBoundedLine reads one newline-terminated line of at most max bytes.
func readBoundedLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		line = append(line, part...)
		if err == nil {
			return bytes.TrimRight(line, "\n"), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		if len(line) > max {
			return nil, fmt.Errorf("line exceeds %d bytes", max)
		}
	}
}

// handleCrashLive logs what the supervisor observes while the app runs.
func handleCrashLive(conn net.Conn, br *bufio.Reader, header types.CrashStreamHeader, lggr logger.Logger) {
	lggr.Infow("enclave live stream connected", "event", "ENCLAVE_LIVE_CONNECTED", "bootID", header.BootID, "app", header.App)
	_ = conn.SetReadDeadline(time.Time{})
	for {
		line, err := readBoundedLine(br, crashLineMaxBytes)
		if err != nil {
			lggr.Warnw("enclave live stream ended", "event", "ENCLAVE_LIVE_ENDED", "bootID", header.BootID, "error", err)
			return
		}
		var msg types.CrashLiveMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			lggr.Warnw("enclave live stream: bad message", "bootID", header.BootID, "error", err)
			continue
		}
		logFn := lggr.Infow
		switch msg.Stream {
		case "gocrash":
			logFn = lggr.Errorw
		case "threads":
			logFn = lggr.Warnw
		}
		enclaveTime := time.Unix(0, msg.UnixNano).UTC().Format(time.RFC3339Nano)
		for part, chunk := range chunkText(strings.Join(msg.Lines, "\n"), 2*crashLogChunkBytes) {
			logFn("enclave live", "event", "ENCLAVE_LIVE", "stream", msg.Stream, "bootID", header.BootID,
				"enclaveTime", enclaveTime, "part", part, "lines", chunk)
		}
	}
}

// handleCrashReport unpacks a report archive: every entry is stored under
// dumpDir and its text logged, then the supervisor is told it can let the
// enclave go.
func handleCrashReport(conn net.Conn, br *bufio.Reader, header types.CrashStreamHeader, lggr logger.Logger, dumpDir string) {
	started := time.Now()
	_ = conn.SetReadDeadline(started.Add(crashReportTimeout))
	lggr.Errorw("enclave crash report incoming", "event", "ENCLAVE_CRASH_REPORT_START", "bootID", header.BootID, "app", header.App)

	dir := filepath.Join(dumpDir, started.UTC().Format("20060102T150405Z")+"-"+header.BootID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		lggr.Errorw("enclave crash report: cannot create dump directory, logging only", "dir", dir, "error", err)
		dir = ""
	}

	// A plain tar: the supervisor compresses the large entries itself, so the
	// host only has to write what arrives.
	tr := tar.NewReader(br)
	entries, total := 0, int64(0)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			lggr.Errorw("enclave crash report: archive cut short", "event", "ENCLAVE_CRASH_REPORT_TRUNCATED",
				"bootID", header.BootID, "entries", entries, "bytes", total, "error", err)
			return
		}
		n := receiveCrashEntry(tr, hdr, header, lggr, dir)
		entries++
		total += n
	}

	lggr.Errorw("enclave crash report stored", "event", "ENCLAVE_CRASH_REPORT_DONE", "bootID", header.BootID,
		"entries", entries, "bytes", total, "dir", dir, "duration", time.Since(started).String())

	_ = conn.SetWriteDeadline(time.Now().Add(crashAckTimeout))
	if _, err := io.WriteString(conn, types.CrashReportAck); err != nil {
		lggr.Warnw("failed to acknowledge enclave crash report", "error", err)
	}
}

// receiveCrashEntry stores one archive entry as received and logs it. Text
// entries are logged in full; anything else (profiles, compressed cores) is
// only summarised. It returns the entry's size.
func receiveCrashEntry(r io.Reader, hdr *tar.Header, header types.CrashStreamHeader, lggr logger.Logger, dir string) int64 {
	name := strings.TrimPrefix(filepath.Clean("/"+hdr.Name), "/")
	isText := strings.HasSuffix(name, ".txt") || name == types.CrashReportFile

	var stored string
	var file *os.File
	if dir != "" {
		stored = filepath.Join(dir, name)
		err := os.MkdirAll(filepath.Dir(stored), 0o700)
		if err == nil {
			file, err = os.OpenFile(stored, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		}
		if err != nil {
			lggr.Errorw("enclave crash report: cannot store entry", "name", name, "error", err)
			stored = ""
		}
	}

	hash := sha256.New()
	keep := &tailBuffer{max: crashLogEntryMaxBytes}
	var storeErr error
	buf := make([]byte, 256<<10)
	var size int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			size += int64(n)
			_, _ = hash.Write(buf[:n])
			if isText {
				_, _ = keep.Write(buf[:n])
			}
			// A full disk must not stall the upload: keep reading, stop writing.
			if file != nil && storeErr == nil {
				_, storeErr = file.Write(buf[:n])
			}
		}
		if err != nil {
			break
		}
	}
	if file != nil {
		if err := file.Close(); storeErr == nil {
			storeErr = err
		}
	}

	fields := []any{"event", "ENCLAVE_CRASH_ARTIFACT", "bootID", header.BootID, "name", name, "bytes", size,
		"sha256", hex.EncodeToString(hash.Sum(nil)), "stored", stored}
	if storeErr != nil {
		fields = append(fields, "storeError", storeErr.Error())
	}

	if name == types.CrashReportFile {
		var report types.CrashReport
		if err := json.Unmarshal(keep.Bytes(), &report); err == nil {
			lggr.Errorw("enclave application exited", "event", "ENCLAVE_APP_EXIT", "bootID", header.BootID,
				"app", report.App, "pid", report.PID, "exitCode", report.ExitCode, "status", report.Status,
				"signal", report.Signal, "coreDumped", report.CoreDumped, "exited", report.Exited,
				"uptimeSeconds", report.UptimeSeconds, "peakRSSBytes", report.PeakRSSBytes,
				"oomKilled", report.OOMKilled, "oomKills", report.OOMKills, "kernelOOMLines", strings.Join(report.KernelOOMLines, "\n"),
				"heartbeatAgeSeconds", report.HeartbeatAgeSeconds, "waitError", report.WaitError)
		}
	}

	if !isText {
		lggr.Errorw("enclave crash artifact", fields...)
		return size
	}
	chunks := chunkText(string(keep.Bytes()), crashLogChunkBytes)
	if len(chunks) == 0 {
		lggr.Errorw("enclave crash artifact", fields...)
	}
	for part, chunk := range chunks {
		lggr.Errorw("enclave crash artifact", append(fields[:len(fields):len(fields)],
			"part", part+1, "parts", len(chunks), "truncatedHead", keep.dropped, "data", chunk)...)
	}
	return size
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max     int
	buf     []byte
	dropped int64
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.dropped += int64(over)
		t.buf = t.buf[over:]
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte { return t.buf }

// chunkText splits text into pieces of at most size bytes, breaking at line
// ends where it can.
func chunkText(text string, size int) []string {
	var chunks []string
	for len(text) > 0 {
		if len(text) <= size {
			chunks = append(chunks, text)
			break
		}
		cut := strings.LastIndexByte(text[:size], '\n')
		if cut <= 0 {
			cut = size
		} else {
			cut++
		}
		chunks = append(chunks, text[:cut])
		text = text[cut:]
	}
	return chunks
}
