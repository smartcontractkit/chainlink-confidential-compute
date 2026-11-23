package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
)

const (
	// Ticks between the slower jobs, in units of config.sampleEvery (200ms).
	ticksPerThreadSample = 5   // 1s
	ticksPerLiveSample   = 25  // 5s
	ticksPerProcSnapshot = 150 // 30s

	// stallAfter is the heartbeat age that counts as a stalled runtime. The app
	// stamps every 50ms.
	stallAfter = 400 * time.Millisecond

	maxCrashSnapshots  = 25
	maxStallSnapshots  = 10
	maxMemorySnapshots = 30
	crashReadChunk     = 512 << 10

	clockTicksPerSecond = 100
)

// procSnapshotFiles are the per-process files kept as "last known" state,
// since /proc/<pid> is gone by the time the app has exited. Cheapest first:
// smaps_rollup walks every page table.
var procSnapshotFiles = []string{"status", "stat", "statm", "maps", "limits", "sched", "io", "cmdline", "environ", "smaps_rollup"}

// pressureLevels are the fractions of total memory left available at which a
// memory snapshot is taken, each once per descent.
var pressureLevels = []float64{0.25, 0.15, 0.08, 0.04}

const (
	// pressureRearm is the available fraction above which the levels arm again.
	pressureRearm = 0.35
	// surgeKB is growth of the app's resident set within one sample that is
	// worth a snapshot on its own, however much memory is still free.
	surgeKB    = 512 << 10
	surgeEvery = 10 * time.Second
)

// memoryWatch turns memory readings into the moments worth a closer look. An
// OOM kill gives the app no chance to say anything, so the evidence has to be
// taken while memory is still climbing.
type memoryWatch struct {
	level     int
	prevRSSKB uint64
	lastSurge time.Time
}

// check returns why the current reading deserves a snapshot, or "".
func (w *memoryWatch) check(now time.Time, totalKB, availKB, rssKB uint64) string {
	prev := w.prevRSSKB
	w.prevRSSKB = rssKB
	if totalKB == 0 {
		return ""
	}
	frac := float64(availKB) / float64(totalKB)
	level := 0
	for i, limit := range pressureLevels {
		if frac < limit {
			level = i + 1
		}
	}
	if level > w.level {
		w.level = level
		return fmt.Sprintf("available memory %s is under %.0f%% of %s (app rss %s)", mib(availKB), pressureLevels[level-1]*100, mib(totalKB), mib(rssKB))
	}
	if frac > pressureRearm {
		w.level = 0
	}
	if prev > 0 && rssKB > prev && rssKB-prev >= surgeKB && now.Sub(w.lastSurge) >= surgeEvery {
		w.lastSurge = now
		return fmt.Sprintf("app rss grew %s in one sample (%s to %s, %s available)", mib(rssKB-prev), mib(prev), mib(rssKB), mib(availKB))
	}
	return ""
}

// sampler watches the app from outside: /proc at a fixed period, the app's
// heartbeat, its trace ring and its fatal-output file. All of it is read-only
// and none of it stops or signals the app.
type sampler struct {
	cfg   config
	pid   int
	live  *liveStream
	notes *notes

	samples *lineRing
	threads *lineRing
	memory  *lineRing

	mu       sync.Mutex
	lastProc map[string]string
	ring     []byte

	lastSeq     uint64
	crashOff    int64
	crashSnaps  int
	stallSince  time.Time
	stallSnaps  int
	prevTicks   map[int]uint64
	prevCPU     uint64
	prevMinFlt  uint64
	prevMajFlt  uint64
	sampledOnce bool

	watch       memoryWatch
	memTotalKB  uint64
	memAvailKB  uint64
	rssKB       uint64
	memSnaps    int
	oomBaseline uint64
	dumpSize    map[string]int64
	dumpSent    map[string]bool

	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func newSampler(cfg config, pid int, live *liveStream, n *notes) *sampler {
	period := cfg.sampleEvery
	if period <= 0 {
		period = 200 * time.Millisecond
	}
	s := &sampler{
		cfg:       cfg,
		pid:       pid,
		live:      live,
		notes:     n,
		samples:   newLineRing(int(3 * time.Minute / period)),
		threads:   newLineRing(4000),
		memory:    newLineRing(4000),
		lastProc:  make(map[string]string),
		prevTicks: make(map[int]uint64),
		dumpSize:  make(map[string]int64),
		dumpSent:  make(map[string]bool),
		done:      make(chan struct{}),
		stopped:   make(chan struct{}),
	}
	s.oomBaseline, _ = vmstatCounter(readString("/proc/vmstat"), "oom_kill")
	return s
}

// oomKills is how many times the kernel's OOM killer has fired since the app
// started.
func (s *sampler) oomKills() uint64 {
	now, ok := vmstatCounter(readString("/proc/vmstat"), "oom_kill")
	if !ok || now < s.oomBaseline {
		return 0
	}
	return now - s.oomBaseline
}

func (s *sampler) proc(name string) string {
	return filepath.Join("/proc", strconv.Itoa(s.pid), name)
}

func (s *sampler) run() {
	defer close(s.stopped)
	ticker := time.NewTicker(s.cfg.sampleEvery)
	defer ticker.Stop()
	for tick := 0; ; tick++ {
		select {
		case <-s.done:
			s.guard("final flush", func() {
				s.forwardCrashOutput(true)
				s.forwardTrace()
				s.forwardAppDumps(true)
			})
			return
		case <-ticker.C:
		}
		s.guard("tick", func() { s.tick(tick) })
	}
}

// stop ends sampling after a final flush of the trace ring and fatal output.
func (s *sampler) stop() {
	s.once.Do(func() { close(s.done) })
	<-s.stopped
}

// guard keeps a collection bug from taking the supervisor down.
func (s *sampler) guard(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.notes.addf("sampler %s panicked: %v", what, r)
		}
	}()
	fn()
}

func (s *sampler) tick(tick int) {
	line := s.processSample()
	s.samples.add(line)
	if tick%ticksPerLiveSample == 0 {
		s.live.send("sample", line)
	}

	// Fatal output appearing means the app is dying right now: its threads are
	// parked where they were, so this is the moment to look at them.
	// The snapshots continue while the process lingers (printing, then dumping
	// core), when the kernel also exposes each thread's user sp and ip.
	if grew := s.forwardCrashOutput(false); (grew || s.crashSnaps > 0) && s.crashSnaps < maxCrashSnapshots {
		if s.crashSnaps == 0 {
			s.notes.addf("fatal runtime output detected, capturing thread and mapping state")
			s.procSnapshot()
			s.forwardTrace()
		}
		s.crashSnaps++
		s.threadSnapshot(true, "crash")
	}

	s.checkHeartbeat()
	if reason := s.watch.check(time.Now(), s.memTotalKB, s.memAvailKB, s.rssKB); reason != "" {
		s.memorySnapshot(reason)
	}

	if tick%ticksPerThreadSample == 0 {
		s.threadSnapshot(false, "")
		s.forwardTrace()
		s.forwardAppDumps(false)
	}
	if tick%ticksPerProcSnapshot == 0 {
		s.procSnapshot()
	}
}

// processSample is one line of process and system state.
func (s *sampler) processSample() string {
	var b strings.Builder
	b.WriteString(time.Now().UTC().Format("15:04:05.000"))

	if _, f, ok := parseStat(readString(s.proc("stat"))); ok {
		cpu := statField(f, statUTime) + statField(f, statSTime)
		minflt, majflt := statField(f, statMinFlt), statField(f, statMajFlt)
		if !s.sampledOnce {
			s.prevCPU, s.prevMinFlt, s.prevMajFlt, s.sampledOnce = cpu, minflt, majflt, true
		}
		fmt.Fprintf(&b, " state=%s thr=%d rss=%s vsz=%s cpu=+%dms flt=+%d/+%d",
			f[0], statField(f, statNumThreads),
			mib(statField(f, statRSSPages)*4), mib(statField(f, statVSize)/1024),
			(cpu-s.prevCPU)*1000/clockTicksPerSecond, minflt-s.prevMinFlt, majflt-s.prevMajFlt)
		s.prevCPU, s.prevMinFlt, s.prevMajFlt = cpu, minflt, majflt
		s.rssKB = statField(f, statRSSPages) * 4
	} else {
		b.WriteString(" state=gone")
	}

	if nanos, count, ok := s.heartbeat(); ok && nanos > 0 {
		fmt.Fprintf(&b, " hb=%dms beats=%d", time.Since(time.Unix(0, nanos)).Milliseconds(), count)
	} else {
		b.WriteString(" hb=-")
	}

	mem := parseKeyedKB(readString("/proc/meminfo"))
	s.memTotalKB, s.memAvailKB = mem["MemTotal"], mem["MemAvailable"]
	fmt.Fprintf(&b, " free=%s avail=%s cached=%s shmem=%s anon=%s slab=%s pgtbl=%s commit=%s",
		mib(mem["MemFree"]), mib(mem["MemAvailable"]), mib(mem["Cached"]), mib(mem["Shmem"]),
		mib(mem["AnonPages"]), mib(mem["Slab"]), mib(mem["PageTables"]), mib(mem["Committed_AS"]))

	fmt.Fprintf(&b, " load=%s psi=%s/%s/%s",
		firstField(readString("/proc/loadavg")),
		parsePressure(readString("/proc/pressure/cpu")),
		parsePressure(readString("/proc/pressure/memory")),
		parsePressure(readString("/proc/pressure/io")))

	if info, err := os.Stat(filepath.Join(s.cfg.crashDir, crashdebug.GoCrashFile)); err == nil {
		fmt.Fprintf(&b, " fatal=%dB", info.Size())
	}
	return b.String()
}

// heartbeat returns the app's last heartbeat from the trace ring header.
func (s *sampler) heartbeat() (unixNano int64, count uint64, ok bool) {
	return crashdebug.ReadBeat(s.mapRing())
}

// mapRing maps the app's trace ring once the app has created it.
func (s *sampler) mapRing() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ring == nil {
		if buf, err := crashdebug.MapRingReadOnly(filepath.Join(s.cfg.crashDir, crashdebug.TraceRingFile)); err == nil {
			s.ring = buf
		}
	}
	return s.ring
}

// checkHeartbeat reports when the app's runtime stops stamping its heartbeat
// while the process is still there, and looks at its threads while it lasts.
func (s *sampler) checkHeartbeat() {
	nanos, _, ok := s.heartbeat()
	if !ok || nanos == 0 {
		return
	}
	age := time.Since(time.Unix(0, nanos))
	switch {
	case age > stallAfter && s.stallSince.IsZero():
		s.stallSince = time.Unix(0, nanos)
		s.stallSnaps = 0
		s.notes.addf("app heartbeat stalled: last beat %s ago", age.Round(time.Millisecond))
		s.threadSnapshot(true, "stall")
	case age > stallAfter && s.stallSnaps < maxStallSnapshots:
		s.stallSnaps++
		s.threadSnapshot(true, "stall")
	case age <= stallAfter && !s.stallSince.IsZero():
		s.notes.addf("app heartbeat resumed after %s", time.Since(s.stallSince).Round(time.Millisecond))
		s.stallSince = time.Time{}
	}
}

// forwardTrace sends the trace records written since the last call.
func (s *sampler) forwardTrace() {
	ring := s.mapRing()
	if ring == nil {
		return
	}
	records, err := crashdebug.ReadRing(ring, s.lastSeq)
	if err != nil || len(records) == 0 {
		return
	}
	lines := make([]string, len(records))
	for i, rec := range records {
		lines[i] = rec.Format()
	}
	s.lastSeq = records[len(records)-1].Seq
	s.live.send("trace", lines...)
}

// forwardCrashOutput sends what the runtime has appended to its fatal-output
// file since the last call and reports whether there was anything. Unless
// final, it holds back a trailing partial line.
func (s *sampler) forwardCrashOutput(final bool) bool {
	f, err := os.Open(filepath.Join(s.cfg.crashDir, crashdebug.GoCrashFile))
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only
	sent := false
	buf := make([]byte, crashReadChunk)
	for {
		n, _ := f.ReadAt(buf, s.crashOff)
		if n == 0 {
			return sent
		}
		data := buf[:n]
		atEOF := n < len(buf)
		if !final || !atEOF {
			if cut := bytes.LastIndexByte(data, '\n'); cut >= 0 {
				data = data[:cut+1]
			} else if atEOF {
				// A partial line is still being written.
				return sent
			}
		}
		s.crashOff += int64(len(data))
		s.live.send("gocrash", strings.Split(strings.TrimRight(string(data), "\n"), "\n")...)
		sent = true
		if atEOF {
			return sent
		}
	}
}

// forwardAppDumps sends the goroutine dumps the app's memory watchdog wrote.
// Unless final, a dump is sent once it has stopped growing.
func (s *sampler) forwardAppDumps(final bool) {
	entries, err := os.ReadDir(s.cfg.crashDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, crashdebug.GoroutineDumpPrefix) || s.dumpSent[name] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		prev, seen := s.dumpSize[name]
		s.dumpSize[name] = info.Size()
		if !final && (!seen || prev != info.Size()) {
			continue
		}
		data := readString(filepath.Join(s.cfg.crashDir, name))
		s.dumpSent[name] = true
		s.notes.addf("app memory watchdog wrote %s (%d bytes)", name, len(data))
		s.live.send("appdump", append([]string{"=== " + name + " ==="}, strings.Split(strings.TrimRight(data, "\n"), "\n")...)...)
	}
}

type threadInfo struct {
	tid   int
	comm  string
	state string
	cpu   uint64
	ticks uint64
	delta uint64
	sp    uint64
	ip    uint64
}

// threadSnapshot records the state of every thread. The short form is one
// line; the detailed form adds, per thread, the user stack and instruction
// pointers, the syscall it is in, what it is waiting on and its kernel stack.
func (s *sampler) threadSnapshot(detail bool, why string) {
	entries, err := os.ReadDir(s.proc("task"))
	if err != nil {
		return
	}
	var threads []threadInfo
	counts := make(map[string]int)
	seen := make(map[int]bool, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, f, ok := parseStat(readString(s.proc(filepath.Join("task", e.Name(), "stat"))))
		if !ok || len(f) == 0 {
			continue
		}
		t := threadInfo{
			tid: tid, comm: comm, state: f[0],
			cpu:   statField(f, statProcessor),
			ticks: statField(f, statUTime) + statField(f, statSTime),
			sp:    statField(f, statKstkESP),
			ip:    statField(f, statKstkEIP),
		}
		if prev, ok := s.prevTicks[tid]; ok && t.ticks >= prev {
			t.delta = t.ticks - prev
		}
		s.prevTicks[tid] = t.ticks
		seen[tid] = true
		counts[t.state]++
		threads = append(threads, t)
	}
	for tid := range s.prevTicks {
		if !seen[tid] {
			delete(s.prevTicks, tid)
		}
	}

	states := make([]string, 0, len(counts))
	for state, n := range counts {
		states = append(states, fmt.Sprintf("%s=%d", state, n))
	}
	sort.Strings(states)
	sort.Slice(threads, func(i, j int) bool { return threads[i].delta > threads[j].delta })

	var head strings.Builder
	fmt.Fprintf(&head, "%s threads n=%d %s", time.Now().UTC().Format("15:04:05.000"), len(threads), strings.Join(states, " "))
	if why != "" {
		fmt.Fprintf(&head, " reason=%s", why)
	}
	head.WriteString(" busy=[")
	listed := 0
	for _, t := range threads {
		if (t.delta == 0 && t.state == "S") || listed == 16 {
			continue
		}
		fmt.Fprintf(&head, "%d:%s:%s:cpu%d:+%dms ", t.tid, t.comm, t.state, t.cpu, t.delta*1000/clockTicksPerSecond)
		listed++
	}
	head.WriteString("]")
	lines := []string{head.String()}

	if detail {
		sort.Slice(threads, func(i, j int) bool { return threads[i].tid < threads[j].tid })
		for _, t := range threads {
			dir := filepath.Join("task", strconv.Itoa(t.tid))
			line := fmt.Sprintf("  tid=%d comm=%s state=%s cpu=%d ticks=%d(+%d) sp=%#x ip=%#x syscall=[%s] wchan=%s",
				t.tid, t.comm, t.state, t.cpu, t.ticks, t.delta, t.sp, t.ip,
				strings.TrimSpace(readString(s.proc(filepath.Join(dir, "syscall")))),
				strings.TrimSpace(readString(s.proc(filepath.Join(dir, "wchan")))))
			if stack := strings.TrimSpace(readString(s.proc(filepath.Join(dir, "stack")))); stack != "" {
				line += " kstack=[" + strings.Join(strings.Fields(strings.ReplaceAll(stack, "\n", " < ")), " ") + "]"
			}
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		s.threads.add(line)
	}
	if detail {
		s.live.send("threads", lines...)
	}
}

// memorySnapshot records where the app's memory is while it is still alive:
// the kernel's accounting for the process, its largest mappings, the system
// counters, and what every thread is doing.
func (s *sampler) memorySnapshot(reason string) {
	if s.memSnaps++; s.memSnaps > maxMemorySnapshots {
		return
	}
	s.notes.addf("memory pressure: %s", reason)
	lines := []string{time.Now().UTC().Format("15:04:05.000") + " memory snapshot: " + reason}

	for _, line := range strings.Split(readString(s.proc("status")), "\n") {
		if strings.HasPrefix(line, "Vm") || strings.HasPrefix(line, "Rss") || strings.HasPrefix(line, "Threads") || strings.HasPrefix(line, "Hugetlb") {
			lines = append(lines, "  status "+strings.Join(strings.Fields(line), " "))
		}
	}
	lines = append(lines, summarizeMaps(readString(s.proc("maps")), 24)...)
	lines = append(lines, "  meminfo "+strings.Join(strings.Fields(strings.ReplaceAll(readString("/proc/meminfo"), "\n", "; ")), " "))
	var counters []string
	for _, line := range strings.Split(readString("/proc/vmstat"), "\n") {
		for _, prefix := range []string{"oom_kill", "allocstall", "pgscan_direct", "pgsteal_direct", "pgfault", "pgmajfault", "compact_stall", "thp_fault_alloc"} {
			if strings.HasPrefix(line, prefix) {
				counters = append(counters, strings.Replace(line, " ", "=", 1))
			}
		}
	}
	lines = append(lines, "  vmstat "+strings.Join(counters, " "))
	for _, line := range lines {
		s.memory.add(line)
	}
	// Sent before the slower reads below, in case the kill comes first.
	s.live.send("memory", lines...)

	s.forwardTrace()
	s.threadSnapshot(true, "memory")
	s.procSnapshot()
	if rollup := s.procSnapshots()["smaps_rollup"]; rollup != "" {
		rollupLines := strings.Split(strings.TrimRight(rollup, "\n"), "\n")
		for _, line := range rollupLines {
			s.memory.add("  smaps_rollup " + strings.Join(strings.Fields(line), " "))
		}
		s.live.send("memory", rollupLines...)
	}
}

// procSnapshot refreshes the kept copy of the per-process files.
func (s *sampler) procSnapshot() {
	stamp := "captured " + time.Now().UTC().Format(time.RFC3339Nano) + "\n"
	for _, name := range procSnapshotFiles {
		data, err := os.ReadFile(s.proc(name))
		if err != nil {
			continue
		}
		content := string(data)
		if name == "cmdline" || name == "environ" {
			content = strings.ReplaceAll(content, "\x00", "\n")
		}
		s.mu.Lock()
		s.lastProc[name] = stamp + content
		s.mu.Unlock()
	}
}

func (s *sampler) procSnapshots() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.lastProc))
	for k, v := range s.lastProc {
		out[k] = v
	}
	return out
}

// traceText renders the whole trace ring, oldest record first.
func (s *sampler) traceText() string {
	ring := s.mapRing()
	if ring == nil {
		return ""
	}
	records, err := crashdebug.ReadRing(ring, 0)
	if err != nil {
		return "unreadable trace ring: " + err.Error() + "\n"
	}
	var b strings.Builder
	for _, rec := range records {
		b.WriteString(rec.Format())
		b.WriteByte('\n')
	}
	return b.String()
}
