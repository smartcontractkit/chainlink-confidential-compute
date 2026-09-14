package server

import (
	"math"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
)

// memInfo holds the /proc/meminfo values the enclave reports. Both come from a
// single read so they describe the same instant: comparing an available figure
// against a total captured a moment later would misstate the headroom.
type memInfo struct {
	// totalBytes is the enclave guest's total RAM (MemTotal). Inside a Nitro
	// enclave this is the guest kernel's view, which runs slightly below the
	// nitro-cli --memory request (kernel/hugepage reservation), so it is an
	// honest measure of usable RAM.
	totalBytes uint64
	// availableBytes is the RAM the kernel reports as available (MemAvailable).
	// This is the real headroom: totalBytes and the process's RSS together
	// cannot show it, because the page cache and slab also draw on the
	// enclave's fixed budget.
	availableBytes uint64
}

// procStatus holds the /proc/self/status values the enclave reports, read
// together for the same reason as memInfo.
type procStatus struct {
	// rssBytes is the process's resident set size (VmRSS). Unlike the Go
	// runtime's own accounting it includes native allocations such as the
	// wasmtime WASM linear memory that dominate the footprint under load.
	rssBytes uint64
	// peakRSSBytes is the high-water mark of that resident set (VmHWM). Being
	// monotonic, it still shows a spike shorter than the host's poll interval,
	// which rssBytes alone would miss between samples.
	peakRSSBytes uint64
}

// readRuntimeMemoryBytes returns the total memory mapped by the Go runtime, in
// bytes. It uses runtime/metrics rather than runtime.ReadMemStats to avoid the
// stop-the-world pause the latter incurs, since this endpoint may be polled
// frequently.
func readRuntimeMemoryBytes() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindUint64 {
		return samples[0].Value.Uint64()
	}
	return 0
}

// readMemInfo reads the enclave guest's memory totals from /proc/meminfo.
// Fields that are absent or malformed stay zero, and an unreadable file yields
// a zero value rather than an error (e.g. non-Linux dev builds, where /proc is
// absent): these are diagnostics, and a missing reading must not fail the
// endpoint reporting it.
func readMemInfo() memInfo {
	var info memInfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return info
	}
	parseSizeFields(data, map[string]*uint64{
		"MemTotal":     &info.totalBytes,
		"MemAvailable": &info.availableBytes,
	})
	return info
}

// readProcStatus reads the enclave process's resident-set figures from
// /proc/self/status, with the same degradation behaviour as readMemInfo.
func readProcStatus() procStatus {
	var status procStatus
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return status
	}
	parseSizeFields(data, map[string]*uint64{
		"VmRSS": &status.rssBytes,
		"VmHWM": &status.peakRSSBytes,
	})
	return status
}

// parseSizeFields extracts the requested "Key: <n> kB" fields into their
// destinations in a single pass. This is the shared format of /proc/meminfo and
// /proc/<pid>/status, so both callers use it.
//
// A field that is absent, malformed, carries a unit other than kB, or would
// overflow leaves its destination untouched; the kB unit is required rather
// than assumed, so a kernel reporting anything else is not silently misread.
// Keys are matched whole, so VmHWM is not satisfied by VmHWMFoo.
func parseSizeFields(data []byte, want map[string]*uint64) {
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		dst, ok := want[key]
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // e.g. ["11534336", "kB"]
		if len(fields) != 2 || fields[1] != "kB" {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kb > math.MaxUint64/1024 {
			continue
		}
		*dst = kb * 1024
	}
}

// bytesToMB rounds a byte count to the nearest megabyte.
func bytesToMB(b uint64) uint64 {
	const mb = 1024 * 1024
	return (b + mb/2) / mb
}
