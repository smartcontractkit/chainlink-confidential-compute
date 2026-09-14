package server

import (
	"math"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
)

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

// readProcessRSSBytes returns the enclave process's resident set size in bytes,
// from /proc/self/status (VmRSS). Unlike readRuntimeMemoryBytes, which sees only
// Go-runtime-mapped memory, RSS includes native allocations such as the wasmtime
// WASM linear memory that dominate the enclave's footprint under load. Returns 0
// if unavailable (e.g. non-Linux dev builds, where /proc is absent).
func readProcessRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	return parseVmRSSBytes(data)
}

// readTotalMemoryBytes returns the enclave guest's total RAM in bytes from
// /proc/meminfo (MemTotal). Inside a Nitro enclave this is the guest kernel's
// MemTotal, which runs slightly below the nitro-cli --memory request
// (kernel/hugepage reservation), so it is an honest measure of usable RAM.
// Returns 0 if unavailable (e.g. non-Linux dev builds, where /proc is absent).
func readTotalMemoryBytes() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotalBytes(data)
}

// readAvailableMemoryBytes returns the guest RAM the kernel reports as
// available in bytes, from /proc/meminfo (MemAvailable). This is the real
// headroom: readTotalMemoryBytes and readProcessRSSBytes together cannot show
// it, because the page cache and slab also draw on the enclave's fixed budget.
// Returns 0 if unavailable (e.g. non-Linux dev builds, where /proc is absent).
func readAvailableMemoryBytes() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseSizeFieldBytes(data, "MemAvailable")
}

// readPeakProcessRSSBytes returns the high-water mark of the enclave process's
// resident set in bytes, from /proc/self/status (VmHWM). Unlike
// readProcessRSSBytes it is monotonic, so a spike shorter than the host's poll
// interval is still visible on the next sample rather than being missed.
// Returns 0 if unavailable (e.g. non-Linux dev builds, where /proc is absent).
func readPeakProcessRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	return parseSizeFieldBytes(data, "VmHWM")
}

// parseSizeFieldBytes extracts the named "Key: <n> kB" field, the shared format
// of /proc/meminfo and /proc/<pid>/status, and returns it in bytes. Returns 0 if
// the field is absent, malformed, carries a unit other than kB, or would
// overflow. Keys are matched whole, so VmHWM is not satisfied by VmHWMFoo.
func parseSizeFieldBytes(data []byte, key string) uint64 {
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, key+":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // e.g. ["11534336", "kB"]
		if len(fields) != 2 || fields[1] != "kB" {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kb > math.MaxUint64/1024 {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// parseMemTotalBytes extracts MemTotal from /proc/meminfo content and returns
// it in bytes (the file reports kB). Returns 0 if the line is absent,
// malformed, carries a unit other than kB, or would overflow.
func parseMemTotalBytes(meminfo []byte) uint64 {
	for _, line := range strings.Split(string(meminfo), "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // e.g. ["11534336", "kB"]
		if len(fields) != 2 || fields[1] != "kB" {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kb > math.MaxUint64/1024 {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// parseVmRSSBytes extracts VmRSS from /proc/<pid>/status content and returns it
// in bytes (the file reports kB). Returns 0 if the line is absent or malformed.
func parseVmRSSBytes(status []byte) uint64 {
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // e.g. ["123456", "kB"]
		if len(fields) < 1 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// bytesToMB rounds a byte count to the nearest megabyte.
func bytesToMB(b uint64) uint64 {
	const mb = 1024 * 1024
	return (b + mb/2) / mb
}
