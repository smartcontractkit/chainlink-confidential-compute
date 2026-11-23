package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// parseStat splits a /proc/<pid>/stat line into the command name and the
// fields that follow it. fields[0] is the state, i.e. field 3 of proc(5).
func parseStat(line string) (comm string, fields []string, ok bool) {
	open := strings.IndexByte(line, '(')
	end := strings.LastIndexByte(line, ')')
	if open < 0 || end < open {
		return "", nil, false
	}
	return line[open+1 : end], strings.Fields(line[end+1:]), true
}

// statField returns proc(5) field number n (1-based, n >= 3) as an integer.
func statField(fields []string, n int) uint64 {
	if i := n - 3; i >= 0 && i < len(fields) {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		return v
	}
	return 0
}

// proc(5) field numbers of /proc/<pid>/stat.
const (
	statMinFlt     = 10
	statMajFlt     = 12
	statUTime      = 14
	statSTime      = 15
	statNumThreads = 20
	statVSize      = 23
	statRSSPages   = 24
	statKstkESP    = 29
	statKstkEIP    = 30
	statProcessor  = 39
)

// parseKeyedKB reads "Key:   123 kB" lines into a map of kilobytes.
func parseKeyedKB(data string) map[string]uint64 {
	out := make(map[string]uint64)
	for _, line := range strings.Split(data, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			out[key] = v
		}
	}
	return out
}

// parsePressure extracts "some avg10" from a /proc/pressure file.
func parsePressure(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(field, "avg10="); ok {
				return v
			}
		}
	}
	return "-"
}

func readString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func firstField(s string) string {
	if fields := strings.Fields(s); len(fields) > 0 {
		return fields[0]
	}
	return "-"
}

func mib(kb uint64) string {
	return fmt.Sprintf("%dMiB", kb/1024)
}

// adjustOOMScores makes the app the OOM killer's victim and exempts the
// supervisor, which has to survive an out-of-memory kill to report it. It
// runs after the app has started, so the exemption is not inherited.
func adjustOOMScores(pid int, n *notes) {
	for _, adj := range [][2]string{
		{"/proc/self/oom_score_adj", "-1000"},
		{fmt.Sprintf("/proc/%d/oom_score_adj", pid), "300"},
	} {
		if err := os.WriteFile(adj[0], []byte(adj[1]), 0o644); err != nil {
			n.addf("oom_score_adj %s=%s failed: %v", adj[0], adj[1], err)
			continue
		}
		n.addf("oom_score_adj %s=%s", adj[0], adj[1])
	}
}

// vmstatCounter returns one counter from /proc/vmstat.
func vmstatCounter(data, name string) (uint64, bool) {
	for _, line := range strings.Split(data, "\n") {
		if key, value, ok := strings.Cut(line, " "); ok && key == name {
			v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}

// uptimeSeconds is the time since boot, the clock kernel log lines carry.
func uptimeSeconds() float64 {
	v, _ := strconv.ParseFloat(firstField(readString("/proc/uptime")), 64)
	return v
}

// kmsgSeconds reads the "[seconds]" stamp formatKmsg puts on a line.
func kmsgSeconds(line string) (float64, bool) {
	end := strings.IndexByte(line, ']')
	if !strings.HasPrefix(line, "[") || end < 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(line[1:end]), 64)
	return v, err == nil
}

// oomLines picks the lines the OOM killer wrote to the kernel log at or after
// the given uptime, so an older kill is not pinned on this app.
func oomLines(kmsg []string, since float64) []string {
	var out []string
	for _, line := range kmsg {
		if at, ok := kmsgSeconds(line); !ok || at < since {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-kill") ||
			strings.Contains(lower, "invoked oom-killer") || strings.Contains(lower, "oom_reaper") {
			out = append(out, line)
		}
	}
	return out
}

// mapping is one line of /proc/<pid>/maps.
type mapping struct {
	start, end uint64
	perms      string
	name       string
}

// parseMaps reads /proc/<pid>/maps.
func parseMaps(data string) []mapping {
	var out []mapping
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		m := mapping{start: start, end: end, perms: fields[1]}
		if len(fields) >= 6 {
			m.name = strings.Join(fields[5:], " ")
		}
		out = append(out, m)
	}
	return out
}

// summarizeMaps totals the address space by kind and lists the largest
// writable mappings, which is where runaway memory shows up.
func summarizeMaps(data string, top int) []string {
	maps := parseMaps(data)
	totals := make(map[string]uint64)
	var writable []mapping
	for _, m := range maps {
		kind := "file"
		switch {
		case m.name == "" && strings.HasPrefix(m.perms, "---"):
			kind = "anon-reserved"
		case m.name == "":
			kind = "anon"
		case strings.HasPrefix(m.name, "["):
			kind = m.name
		}
		totals[kind] += m.end - m.start
		if strings.Contains(m.perms, "w") {
			writable = append(writable, m)
		}
	}
	kinds := make([]string, 0, len(totals))
	for kind := range totals {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return totals[kinds[i]] > totals[kinds[j]] })
	lines := []string{fmt.Sprintf("mappings=%d writable=%d", len(maps), len(writable))}
	for _, kind := range kinds {
		lines = append(lines, fmt.Sprintf("  total %-14s %s", kind, mib(totals[kind]/1024)))
	}
	sort.Slice(writable, func(i, j int) bool {
		return writable[i].end-writable[i].start > writable[j].end-writable[j].start
	})
	for i, m := range writable {
		if i == top {
			break
		}
		lines = append(lines, fmt.Sprintf("  %012x-%012x %s %s %s", m.start, m.end, m.perms, mib((m.end-m.start)/1024), m.name))
	}
	return lines
}
