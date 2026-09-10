package server

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const microsecondsPerSecond = 1_000_000

// readProcessCPUSeconds reads cumulative user and system CPU time from
// getrusage and rounds it to the nearest second. It returns 0 when unavailable
// or below the first rounding boundary. Non-Linux builds are development-only
// and deliberately return 0.
func readProcessCPUSeconds() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return cpuSecondsFromRusage(usage.Utime, usage.Stime)
}

func cpuSecondsFromRusage(user, system unix.Timeval) uint64 {
	microseconds := uint64(user.Sec+system.Sec)*microsecondsPerSecond + uint64(user.Usec+system.Usec)
	return (microseconds + microsecondsPerSecond/2) / microsecondsPerSecond
}

// /proc/stat uses USER_HZ. The enclave kernels use 100 ticks per second;
// utilization is a ratio of equally scaled counters either way.
const procStatClockTicksPerSecond = 100

const (
	cpuUser = iota
	cpuNice
	cpuSystem
	cpuIdle
	cpuIOWait
	cpuIRQ
	cpuSoftIRQ
	cpuSteal
	cpuStatFieldCount
)

// readGuestCPUSeconds reads cumulative whole-guest CPU time from the aggregate
// /proc/stat line. It returns (0, 0) when the sample is unavailable.
func readGuestCPUSeconds() (busy, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	busyTicks, totalTicks, ok := parseGuestCPUTicks(data)
	if !ok {
		return 0, 0
	}
	return cpuTicksToSeconds(busyTicks), cpuTicksToSeconds(totalTicks)
}

// parseGuestCPUTicks extracts cumulative busy and total ticks from the aggregate
// CPU line in /proc/stat. It returns false for missing, malformed, or overflowing data.
func parseGuestCPUTicks(stat []byte) (uint64, uint64, bool) {
	for _, line := range strings.Split(string(stat), "\n") {
		rest, found := strings.CutPrefix(line, "cpu ")
		if !found {
			continue
		}

		fields := strings.Fields(rest)
		var values [cpuStatFieldCount]uint64
		if len(fields) < len(values) {
			return 0, 0, false
		}
		for i := range values {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			values[i] = value
		}

		// guest and guest_nice, when present, are already included in user and
		// nice by Linux and must not be counted again.
		busy, ok := sumCPUTicks(values[cpuUser], values[cpuNice], values[cpuSystem], values[cpuIRQ], values[cpuSoftIRQ])
		if !ok {
			return 0, 0, false
		}
		total, ok := sumCPUTicks(busy, values[cpuIdle], values[cpuIOWait], values[cpuSteal])
		if !ok {
			return 0, 0, false
		}
		return busy, total, true
	}
	return 0, 0, false
}

func sumCPUTicks(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, false
		}
		total += value
	}
	return total, true
}

// cpuTicksToSeconds rounds without adding first, which could overflow uint64.
func cpuTicksToSeconds(ticks uint64) uint64 {
	seconds := ticks / procStatClockTicksPerSecond
	if ticks%procStatClockTicksPerSecond >= procStatClockTicksPerSecond/2 {
		seconds++
	}
	return seconds
}
