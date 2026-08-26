package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVmRSSBytes(t *testing.T) {
	const status = `Name:	go-enclave
Umask:	0022
State:	R (running)
VmPeak:	 2100000 kB
VmSize:	 2000000 kB
VmRSS:	 1234560 kB
RssAnon:	 1200000 kB
Threads:	42
`
	if got, want := parseVmRSSBytes([]byte(status)), uint64(1234560)*1024; got != want {
		t.Fatalf("parseVmRSSBytes = %d, want %d", got, want)
	}

	cases := map[string][]byte{
		"missing line": []byte("Name:\tx\nVmSize:\t100 kB\n"),
		"empty input":  []byte(""),
		"malformed":    []byte("VmRSS:\tnotanumber kB\n"),
		"no value":     []byte("VmRSS:\n"),
	}
	for name, in := range cases {
		if got := parseVmRSSBytes(in); got != 0 {
			t.Errorf("%s: parseVmRSSBytes = %d, want 0", name, got)
		}
	}
}

func TestParseMemTotalBytes(t *testing.T) {
	const meminfo = `MemTotal:       11534336 kB
MemFree:         8123456 kB
MemAvailable:    9000000 kB
Buffers:          123456 kB
`
	if got, want := parseMemTotalBytes([]byte(meminfo)), uint64(11534336)*1024; got != want {
		t.Fatalf("parseMemTotalBytes() = %d, want %d", got, want)
	}
	if got := parseMemTotalBytes([]byte("no memtotal here")); got != 0 {
		t.Fatalf("parseMemTotalBytes() = %d, want 0", got)
	}
	if got := parseMemTotalBytes([]byte("MemTotal: notanumber kB")); got != 0 {
		t.Fatalf("parseMemTotalBytes() = %d, want 0", got)
	}

	cases := map[string]string{
		"wrong unit":    "MemTotal: 11534336 MB",
		"missing unit":  "MemTotal: 11534336",
		"extra field":   "MemTotal: 11534336 kB extra",
		"overflow":      "MemTotal: 18014398509481984 kB", // > MaxUint64/1024
		"negative":      "MemTotal: -1 kB",
		"lowercase kib": "MemTotal: 11534336 kb",
	}
	for name, in := range cases {
		if got := parseMemTotalBytes([]byte(in)); got != 0 {
			t.Errorf("%s: parseMemTotalBytes() = %d, want 0", name, got)
		}
	}
}

func TestBytesToMBQuantizesMemoryReport(t *testing.T) {
	t.Parallel()

	const mib = uint64(1024 * 1024)
	tests := []struct {
		name  string
		bytes uint64
		want  uint64
	}{
		{name: "zero", bytes: 0, want: 0},
		{name: "below half MiB", bytes: mib/2 - 1, want: 0},
		{name: "half MiB rounds up", bytes: mib / 2, want: 1},
		{name: "below one and a half MiB", bytes: mib + mib/2 - 1, want: 1},
		{name: "one and a half MiB rounds up", bytes: mib + mib/2, want: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.want, bytesToMB(test.bytes))
		})
	}
}

// configureTestServer POSTs a minimal non-zero config so the server will serve
// /publicKeys. Tests that only need keys served (not the unconfigured 503
// behavior) call this right after startup.
