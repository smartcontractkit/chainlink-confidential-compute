package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// systemFiles are read once, after the app has exited.
var systemFiles = []string{
	"meminfo", "vmstat", "loadavg", "uptime", "cpuinfo", "cmdline", "version", "mounts",
	"buddyinfo", "interrupts", "stat", "pressure/cpu", "pressure/memory", "pressure/io",
	"sys/kernel/core_pattern", "sys/kernel/osrelease", "sys/vm/overcommit_memory",
}

// entry is one file of the report archive: data held in memory, or a file on
// disk streamed from path. With compress, the file is gzipped just before it
// is sent and arrives as name+".gz"; size is always the uncompressed size.
type entry struct {
	name     string
	data     []byte
	path     string
	compress bool
	size     int64
}

// coreCompressWorkers is how many ranges of a core file are compressed at
// once. The app is dead by then, so its vCPUs are free.
const coreCompressWorkers = 4

// collectArtifacts gathers everything the supervisor knows once the app is
// gone. Core files go last so a cut-off upload still delivers the rest.
func collectArtifacts(cfg config, app string, smp *sampler, kmsg *kmsgReader, n *notes) []entry {
	var entries []entry
	add := func(name, content string) {
		if content != "" {
			entries = append(entries, entry{name: name, data: []byte(content), size: int64(len(content))})
		}
	}

	add(crashdebug.GoCrashFile, readString(filepath.Join(cfg.crashDir, crashdebug.GoCrashFile)))
	add("trace.txt", smp.traceText())
	kmsg.flush()
	add("kmsg.txt", joinLines(kmsg.ring.snapshot()))
	add("samples.txt", joinLines(smp.samples.snapshot()))
	add("threads.txt", joinLines(smp.threads.snapshot()))
	add("memory.txt", joinLines(smp.memory.snapshot()))

	snapshots := smp.procSnapshots()
	names := make([]string, 0, len(snapshots))
	for name := range snapshots {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add("proc-last/"+name+".txt", snapshots[name])
	}
	for _, name := range systemFiles {
		add("system/"+strings.ReplaceAll(name, "/", "_")+".txt", readString(filepath.Join("/proc", name)))
	}
	add("buildinfo.txt", describeBinary(app))

	// Everything else in the crash directory: the dumps the app wrote when its
	// memory watchdog fired, then core files.
	var listing strings.Builder
	var appFiles, cores []entry
	if dir, err := os.ReadDir(cfg.crashDir); err == nil {
		for _, e := range dir {
			info, err := e.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(&listing, "%12d %s %s\n", info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano), e.Name())
			if !info.Mode().IsRegular() || info.Size() == 0 || e.Name() == crashdebug.TraceRingFile || e.Name() == crashdebug.GoCrashFile {
				continue
			}
			file := entry{path: filepath.Join(cfg.crashDir, e.Name()), size: info.Size()}
			if strings.HasPrefix(e.Name(), "core") {
				file.name = "core/" + e.Name()
				file.compress = true
				cores = append(cores, file)
				n.addf("core file %s: %d bytes", e.Name(), info.Size())
				continue
			}
			file.name = "app/" + e.Name()
			appFiles = append(appFiles, file)
		}
	}
	add("crashdir.txt", listing.String())
	if len(cores) == 0 {
		n.addf("no core file in %s", cfg.crashDir)
	}
	return append(append(entries, appFiles...), cores...)
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// describeBinary reports the app's digest and embedded module versions, which
// is what a core or a raw program counter has to be symbolised against.
func describeBinary(path string) string {
	var b strings.Builder
	if f, err := os.Open(path); err == nil {
		h := sha256.New()
		size, _ := io.Copy(h, f)
		_ = f.Close()
		fmt.Fprintf(&b, "path: %s\nsize: %d\nsha256: %s\n", path, size, hex.EncodeToString(h.Sum(nil)))
	}
	if info, err := buildinfo.ReadFile(path); err == nil {
		b.WriteString(info.String())
	} else {
		fmt.Fprintf(&b, "build info unavailable: %v\n", err)
	}
	return b.String()
}

// printSummary writes the headline facts to the enclave console.
func printSummary(w io.Writer, report types.CrashReport, smp *sampler) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n===== ENCLAVE APP EXIT boot=%s =====\n", report.BootID)
	fmt.Fprintf(&b, "status=%q exit_code=%d signal=%q core_dumped=%v uptime=%.3fs exited=%s\n",
		report.Status, report.ExitCode, report.Signal, report.CoreDumped, report.UptimeSeconds, report.Exited)
	fmt.Fprintf(&b, "oom_killed=%v oom_kills=%d\n", report.OOMKilled, report.OOMKills)
	for _, line := range report.KernelOOMLines {
		b.WriteString("  kernel: " + line + "\n")
	}
	fmt.Fprintf(&b, "peak_rss=%dMiB user_cpu=%.1fs sys_cpu=%.1fs minflt=%d majflt=%d ctxsw=%d/%d heartbeat_age=%.3fs\n",
		report.PeakRSSBytes>>20, report.UserCPUSeconds, report.SystemCPUSeconds, report.MinorFaults, report.MajorFaults,
		report.VoluntaryCtxSwitches, report.InvoluntaryCtxSwitch, report.HeartbeatAgeSeconds)
	b.WriteString("--- last samples ---\n")
	b.WriteString(joinLines(tail(smp.samples.snapshot(), 15)))
	b.WriteString("--- memory snapshots ---\n")
	b.WriteString(joinLines(tail(smp.memory.snapshot(), 80)))
	b.WriteString("--- last trace records ---\n")
	b.WriteString(joinLines(tail(strings.Split(strings.TrimRight(smp.traceText(), "\n"), "\n"), 120)))
	b.WriteString("===== END ENCLAVE APP EXIT =====\n")
	_, _ = io.WriteString(w, b.String())
}

func tail(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

// sendReport uploads the report archive and waits for the host to confirm it
// stored it. The whole exchange is bounded by cfg.reportTimeout.
func sendReport(cfg config, report *types.CrashReport, entries []entry, n *notes) {
	deadline := time.Now().Add(cfg.reportTimeout)
	report.Files = make(map[string]int64, len(entries))
	for _, e := range entries {
		report.Files[e.name] = e.size
	}

	conn, err := dialHostTimeout(cfg.dialTimeout)
	for attempt := 1; err != nil && attempt < 5; attempt++ {
		time.Sleep(time.Second)
		conn, err = dialHostTimeout(cfg.dialTimeout)
	}
	if err != nil {
		n.addf("crash report not sent, cannot reach the host: %v", err)
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup
	if err := conn.SetDeadline(deadline); err != nil {
		n.addf("cannot set crash report deadline: %v", err)
	}

	started := time.Now()
	report.Notes = n.snapshot()
	bw := bufio.NewWriterSize(conn, 256<<10)
	header := types.CrashStreamHeader{Kind: types.CrashStreamReport, BootID: report.BootID, App: report.App, UnixNano: started.UnixNano()}
	if err := json.NewEncoder(bw).Encode(header); err != nil {
		n.addf("crash report header failed: %v", err)
		return
	}
	sent, err := writeArchive(bw, *report, entries, cfg.crashDir, deadline, n)
	if err == nil {
		err = bw.Flush()
	}
	if err != nil {
		n.addf("crash report upload failed after %d bytes: %v", sent, err)
		return
	}

	ack := make([]byte, len(types.CrashReportAck))
	if _, err := io.ReadFull(conn, ack); err != nil || string(ack) != types.CrashReportAck {
		n.addf("crash report sent (%d bytes) but not acknowledged: %v", sent, err)
		return
	}
	n.addf("crash report delivered: %d entries, %d bytes, %s", len(entries)+1, sent, time.Since(started).Round(time.Millisecond))
}

// writeArchive writes report.json and the entries as a tar stream and returns
// the bytes of content written. The stream itself is not compressed: text is
// small, vsock is fast, and the host has little CPU to spend. Core files are
// the exception and are compressed here, in scratch, before they are sent.
func writeArchive(w io.Writer, report types.CrashReport, entries []entry, scratch string, deadline time.Time, n *notes) (int64, error) {
	tw := tar.NewWriter(w)
	now := time.Now()
	var total int64

	writeBytes := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now}); err != nil {
			return err
		}
		written, err := tw.Write(data)
		total += int64(written)
		return err
	}

	summary, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeBytes(types.CrashReportFile, summary); err != nil {
		return total, err
	}
	for _, e := range entries {
		switch {
		case e.path == "":
			err = writeBytes(e.name, e.data)
		case e.compress:
			// Leave the last stretch of the budget for the transfer itself.
			parts, size, cerr := compressParallel(e.path, scratch, coreCompressWorkers, deadline.Add(-15*time.Second))
			if cerr != nil {
				n.addf("compressing %s failed: %v", e.name, cerr)
				err = writeBytes(e.name+".failed.txt", []byte(cerr.Error()+"\n"))
			} else {
				n.addf("compressed %s: %d to %d bytes", e.name, e.size, size)
				var written int64
				written, err = writeFiles(tw, e.name+".gz", parts, size, now)
				total += written
			}
			for _, part := range parts {
				_ = os.Remove(part)
			}
		default:
			var written int64
			written, err = writeFiles(tw, e.name, []string{e.path}, e.size, now)
			total += written
		}
		if err != nil {
			return total, err
		}
	}
	return total, tw.Close()
}

// writeFiles streams the concatenation of paths into the archive as one entry
// of the given size. Content that turns out shorter than the header says is
// padded with zeros so the archive stays well formed.
func writeFiles(tw *tar.Writer, name string, paths []string, size int64, modTime time.Time) (int64, error) {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: modTime}); err != nil {
		return 0, err
	}
	var written int64
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			break
		}
		n, err := io.CopyN(tw, f, size-written)
		_ = f.Close()
		written += n
		if err != nil && err != io.EOF {
			return written, err
		}
	}
	if written < size {
		padded, err := io.CopyN(tw, zeroReader{}, size-written)
		return written + padded, err
	}
	return written, nil
}

// compressParallel gzips path as consecutive ranges, several at once, into
// files under dir. Read back in order they form one valid gzip stream of the
// whole file. It returns the part files and their total size.
func compressParallel(path, dir string, workers int, deadline time.Time) ([]string, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	chunk := (size + int64(workers) - 1) / int64(workers)
	if chunk == 0 {
		chunk = 1
	}

	var parts []string
	var offsets []int64
	for off := int64(0); off < size; off += chunk {
		parts = append(parts, filepath.Join(dir, fmt.Sprintf(".%s.part%d.gz", filepath.Base(path), len(parts))))
		offsets = append(offsets, off)
	}
	sizes := make([]int64, len(parts))
	errs := make([]error, len(parts))
	var wg sync.WaitGroup
	for i := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sizes[i], errs[i] = compressRange(path, parts[i], offsets[i], min(chunk, size-offsets[i]), deadline)
		}()
	}
	wg.Wait()

	var total int64
	for i := range parts {
		if errs[i] != nil {
			return parts, 0, errs[i]
		}
		total += sizes[i]
	}
	return parts, total, nil
}

// compressRange gzips length bytes of src starting at off into dst.
func compressRange(src, dst string, off, length int64, deadline time.Time) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close() //nolint:errcheck // read-only
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close() //nolint:errcheck // closed explicitly on success
	gz, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		return 0, err
	}

	reader := io.NewSectionReader(in, off, length)
	buf := make([]byte, 1<<20)
	for {
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("ran out of time compressing %s", filepath.Base(src))
		}
		n, rerr := reader.Read(buf)
		if n > 0 {
			if _, werr := gz.Write(buf[:n]); werr != nil {
				return 0, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return 0, rerr
		}
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	info, err := os.Stat(dst)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
