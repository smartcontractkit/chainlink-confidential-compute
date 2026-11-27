package crashdebug

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRingRoundTripAndWrap(t *testing.T) {
	const slotSize, slots = 64, 8
	buf := make([]byte, RingSize(slotSize, slots))
	ring, err := NewRing(buf, slotSize, slots)
	require.NoError(t, err)

	for i := 1; i <= 20; i++ {
		ring.Write(int64(i), strings.Repeat("x", i))
	}

	records, err := ReadRing(buf, 0)
	require.NoError(t, err)
	require.Len(t, records, slots)
	// Oldest surviving record is 13; the ring kept the newest eight in order.
	for i, rec := range records {
		require.Equal(t, uint64(13+i), rec.Seq)
		require.Equal(t, int64(13+i), rec.UnixNano)
		require.Equal(t, strings.Repeat("x", 13+i), rec.Msg)
	}

	tail, err := ReadRing(buf, 18)
	require.NoError(t, err)
	require.Len(t, tail, 2)
	require.Equal(t, uint64(19), tail[0].Seq)
}

func TestRingTruncatesLongRecords(t *testing.T) {
	const slotSize, slots = 32, 2
	buf := make([]byte, RingSize(slotSize, slots))
	ring, err := NewRing(buf, slotSize, slots)
	require.NoError(t, err)

	ring.Write(1, strings.Repeat("y", 100))
	records, err := ReadRing(buf, 0)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, strings.Repeat("y", slotSize-slotHeaderSize), records[0].Msg)
}

func TestReadRingRejectsGarbage(t *testing.T) {
	_, err := ReadRing(make([]byte, 128), 0)
	require.Error(t, err)
	_, _, ok := ReadBeat(make([]byte, 128))
	require.False(t, ok)
}

func TestInitMapsRingThatSurvivesInTheFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvCrashDir, dir)
	t.Cleanup(func() { active.Store(nil) })

	var steps []string
	Init(func(format string, args ...any) { steps = append(steps, format) })
	require.True(t, Enabled(), "steps: %v", steps)

	Tracef("hello %s", "ring")
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(filepath.Join(dir, TraceRingFile))
		if err != nil {
			return false
		}
		_, count, ok := ReadBeat(data)
		return ok && count > 0
	}, 5*time.Second, 20*time.Millisecond, "heartbeat never reached the file")

	// Read through the file, as the supervisor does after the app is gone.
	data, err := os.ReadFile(filepath.Join(dir, TraceRingFile))
	require.NoError(t, err)
	records, err := ReadRing(data, 0)
	require.NoError(t, err)
	var found bool
	for _, rec := range records {
		found = found || rec.Msg == "hello ring"
	}
	require.True(t, found, "records: %v", records)
	require.FileExists(t, filepath.Join(dir, GoCrashFile))
}

func TestTracefIsInertWithoutInit(t *testing.T) {
	active.Store(nil)
	require.False(t, Enabled())
	Tracef("dropped %d", 1)
}

func TestTag(t *testing.T) {
	require.Equal(t, "-", Tag(context.Background()))
	require.Equal(t, "abc", Tag(WithTag(context.Background(), "abc")))
}

func TestRuntimeStatsNamesMetrics(t *testing.T) {
	stats := runtimeStats()
	require.Contains(t, stats, "sched_goroutines=")
	require.Contains(t, stats, "classes_total=")
	require.Equal(t, "heap_objects", metricLabel("/memory/classes/heap/objects:bytes"))
}

func TestMemoryWatchLevelsAndSurge(t *testing.T) {
	const gib = uint64(1) << 30
	now := time.Unix(1000, 0)
	w := memoryWatch{total: 10 * gib}

	require.Empty(t, w.check(now, 2*gib), "normal resident set")
	require.Contains(t, w.check(now, 4*gib+1), "reached 40%")
	require.Empty(t, w.check(now, 4*gib+2), "a level reports once per climb")
	// Skipping a level reports the deepest one reached.
	require.Contains(t, w.check(now, 9*gib), "reached 80%")
	require.Empty(t, w.check(now, 9*gib))

	// Falling back under the re-arm fraction arms the levels again.
	require.Empty(t, w.check(now, 2*gib))
	require.Contains(t, w.check(now, 6*gib), "reached 60%")

	// A jump between two checks triggers on its own, at most once per window.
	s := memoryWatch{total: 100 * gib}
	require.Empty(t, s.check(now, 1*gib))
	require.Contains(t, s.check(now, 2*gib), "rss grew 1024 MiB")
	require.Empty(t, s.check(now.Add(time.Second), 3*gib), "rate limited")
	require.Contains(t, s.check(now.Add(time.Minute), 4*gib), "rss grew")

	// Without a known total only the surge applies.
	u := memoryWatch{}
	require.Empty(t, u.check(now, 9*gib))
	require.Contains(t, u.check(now, 10*gib), "rss grew")
	require.Empty(t, u.check(now, 0), "an unreadable resident set never triggers")
}

func TestDumpMemoryStateWritesStacksAndHeapProfile(t *testing.T) {
	dir := t.TempDir()
	dumpMemoryState(dir, 3, 5<<30, "test pressure")

	stacks, err := os.ReadFile(filepath.Join(dir, GoroutineDumpPrefix+"03.txt"))
	require.NoError(t, err)
	require.Contains(t, string(stacks), "memory watchdog #3")
	require.Contains(t, string(stacks), "test pressure")
	require.Contains(t, string(stacks), "TestDumpMemoryStateWritesStacksAndHeapProfile")
	require.Contains(t, string(stacks), "go.total=")

	profile, err := os.ReadFile(filepath.Join(dir, HeapProfilePrefix+"03.pprof"))
	require.NoError(t, err)
	// A pprof profile is gzip-compressed protobuf.
	require.Equal(t, []byte{0x1f, 0x8b}, profile[:2])
}
