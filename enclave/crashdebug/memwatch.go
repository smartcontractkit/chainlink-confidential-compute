package crashdebug

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/metrics"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The kernel's OOM killer ends the process with SIGKILL, which the runtime
// never sees: no traceback, no chance to say what was allocating. So the app
// watches its own resident set and, while memory is still climbing, writes
// what a post-mortem would want into the crash directory, where the files
// outlive the process.

const (
	// GoroutineDumpPrefix and HeapProfilePrefix name the files the memory
	// watchdog writes, followed by a sequence number.
	GoroutineDumpPrefix = "goroutines-"
	HeapProfilePrefix   = "heap-"

	// memoryCheckEveryBeats spaces the checks at 200ms.
	memoryCheckEveryBeats = 4
	maxMemoryDumps        = 12

	// memoryRearm is the fraction of total memory the resident set has to fall
	// back under before the levels trigger again.
	memoryRearm = 0.30
	// memorySurgeBytes is growth between two checks that triggers a dump
	// whatever the absolute level.
	memorySurgeBytes = 512 << 20
	memorySurgeEvery = 10 * time.Second
)

// memoryLevels are the fractions of total memory at which the resident set
// triggers a dump, each once per climb. The enclave normally sits near 20%.
var memoryLevels = []float64{0.40, 0.60, 0.80}

// memoryWatch decides when the resident set warrants a dump.
type memoryWatch struct {
	total     uint64
	level     int
	prevRSS   uint64
	lastSurge time.Time
}

// check returns why the current resident set deserves a dump, or "".
func (w *memoryWatch) check(now time.Time, rss uint64) string {
	prev := w.prevRSS
	w.prevRSS = rss
	if rss == 0 {
		return ""
	}
	if w.total > 0 {
		frac := float64(rss) / float64(w.total)
		level := 0
		for i, limit := range memoryLevels {
			if frac >= limit {
				level = i + 1
			}
		}
		if level > w.level {
			w.level = level
			return fmt.Sprintf("rss %d MiB reached %.0f%% of %d MiB", rss>>20, memoryLevels[level-1]*100, w.total>>20)
		}
		if frac < memoryRearm {
			w.level = 0
		}
	}
	if prev > 0 && rss > prev && rss-prev >= memorySurgeBytes && now.Sub(w.lastSurge) >= memorySurgeEvery {
		w.lastSurge = now
		return fmt.Sprintf("rss grew %d MiB between checks (%d to %d MiB)", (rss-prev)>>20, prev>>20, rss>>20)
	}
	return ""
}

// readRSSBytes is the process's resident set from /proc/self/statm.
func readRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, _ := strconv.ParseUint(fields[1], 10, 64)
	return pages * uint64(os.Getpagesize())
}

// readMemTotalBytes is the machine's memory from /proc/meminfo.
func readMemTotalBytes() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				kb, _ := strconv.ParseUint(fields[0], 10, 64)
				return kb << 10
			}
		}
	}
	return 0
}

var memoryDumpRunning atomic.Bool

// dumpMemoryState writes every goroutine's stack and a heap profile into dir
// and records the runtime's memory classes in the trace ring. The goroutine
// stacks come first: they say what each execution was doing as memory grew.
func dumpMemoryState(dir string, seq int, rss uint64, reason string) {
	if !memoryDumpRunning.CompareAndSwap(false, true) {
		return
	}
	defer memoryDumpRunning.Store(false)

	started := time.Now()
	Tracef("memory watchdog #%d: %s; rss=%dMiB %s", seq, reason, rss>>20, memoryClasses())

	goroutines := filepath.Join(dir, fmt.Sprintf("%s%02d.txt", GoroutineDumpPrefix, seq))
	if f, err := os.Create(goroutines); err == nil {
		_, _ = fmt.Fprintf(f, "memory watchdog #%d at %s: %s\nrss=%dMiB %s\n\n", seq, started.UTC().Format(time.RFC3339Nano), reason, rss>>20, memoryClasses())
		_ = pprof.Lookup("goroutine").WriteTo(f, 2)
		_ = f.Close()
	}
	Tracef("memory watchdog #%d: goroutine stacks written after %s", seq, time.Since(started))

	heap := filepath.Join(dir, fmt.Sprintf("%s%02d.pprof", HeapProfilePrefix, seq))
	if f, err := os.Create(heap); err == nil {
		_ = pprof.Lookup("heap").WriteTo(f, 0)
		_ = f.Close()
	}
	Tracef("memory watchdog #%d: heap profile written after %s", seq, time.Since(started))
}

// memoryClasses renders the runtime's own memory accounting. Whatever the
// resident set holds beyond its total is native memory (wasmtime, cgo).
func memoryClasses() string {
	var samples []metrics.Sample
	for _, d := range metrics.All() {
		if strings.HasPrefix(d.Name, "/memory/classes/") && d.Kind == metrics.KindUint64 {
			samples = append(samples, metrics.Sample{Name: d.Name})
		}
	}
	metrics.Read(samples)
	var b strings.Builder
	for _, s := range samples {
		if s.Value.Kind() != metrics.KindUint64 || s.Value.Uint64() == 0 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(s.Name, "/memory/classes/"), ":bytes")
		fmt.Fprintf(&b, "go.%s=%dMiB ", name, s.Value.Uint64()>>20)
	}
	return strings.TrimSpace(b.String())
}
