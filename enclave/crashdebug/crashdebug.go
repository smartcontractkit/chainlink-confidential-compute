package crashdebug

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// EnvCrashDir names the directory the supervisor prepared for crash
	// artifacts. The recorder is inert unless it is set.
	EnvCrashDir = "ENCLAVE_CRASH_DIR"

	// TraceRingFile and GoCrashFile are the files the app writes into the
	// crash directory.
	TraceRingFile = "trace.ring"
	GoCrashFile   = "go-crash.txt"

	// HeartbeatInterval is how often the app stamps the ring header.
	HeartbeatInterval = 50 * time.Millisecond

	// lateBeatThreshold is the scheduling delay worth a trace record.
	lateBeatThreshold = 100 * time.Millisecond
)

var active atomic.Pointer[Ring]

// Enabled reports whether trace records are being kept.
func Enabled() bool { return active.Load() != nil }

// Init turns the recorder on when the supervisor provided a crash directory.
// It mirrors fatal runtime output to a file, maps the trace ring and starts the
// heartbeat. logf receives one line per step.
func Init(logf func(format string, args ...any)) {
	dir := os.Getenv(EnvCrashDir)
	if dir == "" {
		logf("crashdebug: %s not set, flight recorder disabled", EnvCrashDir)
		return
	}

	// "crash" prints every goroutine, runtime frames and registers, then aborts
	// so the kernel can write a core.
	debug.SetTraceback("crash")

	crashPath := filepath.Join(dir, GoCrashFile)
	if f, err := os.OpenFile(crashPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err != nil {
		logf("crashdebug: cannot open %s: %v", crashPath, err)
	} else if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		logf("crashdebug: SetCrashOutput: %v", err)
	} else {
		logf("crashdebug: fatal runtime output mirrored to %s", crashPath)
	}

	ringPath := filepath.Join(dir, TraceRingFile)
	buf, err := mapFile(ringPath, RingSize(DefaultSlotSize, DefaultSlots))
	if err != nil {
		logf("crashdebug: cannot map %s: %v", ringPath, err)
		return
	}
	// Touch every page now. The filesystem allocates a page on first write, and
	// a record written later must never be the write that finds none left.
	for i := 0; i < len(buf); i += os.Getpagesize() {
		buf[i] = 0
	}
	ring, err := NewRing(buf, DefaultSlotSize, DefaultSlots)
	if err != nil {
		logf("crashdebug: %v", err)
		return
	}
	active.Store(ring)
	logf("crashdebug: trace ring mapped at %s (%d slots of %d bytes)", ringPath, DefaultSlots, DefaultSlotSize)

	Tracef("init pid=%d go=%s gomaxprocs=%d numcpu=%d args=%q", os.Getpid(), runtime.Version(), runtime.GOMAXPROCS(0), runtime.NumCPU(), os.Args)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if strings.Contains(dep.Path, "wasmtime") || strings.Contains(dep.Path, "chainlink-common") {
				Tracef("dep %s %s", dep.Path, dep.Version)
			}
		}
	}
	go heartbeat(ring, dir)
}

// Tracef appends one record to the trace ring. It is a no-op until Init has
// mapped the ring.
func Tracef(format string, args ...any) {
	ring := active.Load()
	if ring == nil {
		return
	}
	ring.Write(time.Now().UnixNano(), fmt.Sprintf(format, args...))
}

type tagKey struct{}

// WithTag attaches an execution label that Tag returns further down the call.
func WithTag(ctx context.Context, tag string) context.Context {
	return context.WithValue(ctx, tagKey{}, tag)
}

// Tag returns the execution label attached by WithTag, or "-".
func Tag(ctx context.Context) string {
	if tag, ok := ctx.Value(tagKey{}).(string); ok {
		return tag
	}
	return "-"
}

var runtimeSamples = []metrics.Sample{
	{Name: "/sched/goroutines:goroutines"},
	{Name: "/memory/classes/total:bytes"},
	{Name: "/memory/classes/heap/objects:bytes"},
	{Name: "/memory/classes/heap/released:bytes"},
	{Name: "/gc/cycles/total:gc-cycles"},
	{Name: "/gc/heap/goal:bytes"},
	{Name: "/cgo/go-to-c-calls:calls"},
}

// heartbeat stamps the ring header every interval, records ticks that arrive
// late (the whole runtime was held up), writes runtime counters once a second
// and runs the memory watchdog.
func heartbeat(ring *Ring, dir string) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	var count uint64
	prev := time.Now()
	lastStats := prev
	watch := memoryWatch{total: readMemTotalBytes()}
	dumps := 0
	Tracef("memory watchdog armed: total=%dMiB levels=%v surge=%dMiB", watch.total>>20, memoryLevels, memorySurgeBytes>>20)
	for range ticker.C {
		count++
		now := time.Now()
		ring.Beat(now.UnixNano(), count)
		if late := now.Sub(prev) - HeartbeatInterval; late > lateBeatThreshold {
			Tracef("heartbeat late by %s (runtime stalled)", late)
		}
		prev = now
		if count%memoryCheckEveryBeats == 0 {
			rss := readRSSBytes()
			if reason := watch.check(now, rss); reason != "" && dumps < maxMemoryDumps {
				dumps++
				// Off this goroutine, so the heartbeat keeps its rhythm.
				go dumpMemoryState(dir, dumps, rss, reason)
			}
		}
		if now.Sub(lastStats) >= time.Second {
			lastStats = now
			Tracef("runtime %s threads=%d rss=%dMiB", runtimeStats(), threadCount(), readRSSBytes()>>20)
		}
	}
}

func runtimeStats() string {
	samples := make([]metrics.Sample, len(runtimeSamples))
	copy(samples, runtimeSamples)
	metrics.Read(samples)
	var b strings.Builder
	for _, s := range samples {
		switch s.Value.Kind() {
		case metrics.KindUint64:
			fmt.Fprintf(&b, "%s=%d ", metricLabel(s.Name), s.Value.Uint64())
		case metrics.KindFloat64:
			fmt.Fprintf(&b, "%s=%g ", metricLabel(s.Name), s.Value.Float64())
		}
	}
	return strings.TrimSpace(b.String())
}

// metricLabel shortens "/memory/classes/heap/objects:bytes" to "heap_objects".
func metricLabel(name string) string {
	path, _, _ := strings.Cut(name, ":")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "_" + parts[len(parts)-1]
	}
	return parts[len(parts)-1]
}

// threadCount is the number of OS threads the runtime has created.
func threadCount() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}
