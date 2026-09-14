package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSizeFieldsMemInfo(t *testing.T) {
	const meminfo = `MemTotal:       11534336 kB
MemFree:         8123456 kB
MemAvailable:    9000000 kB
Buffers:          123456 kB
`
	var total, available uint64
	parseSizeFields([]byte(meminfo), map[string]*uint64{
		"MemTotal":     &total,
		"MemAvailable": &available,
	})

	if want := uint64(11534336) * 1024; total != want {
		t.Errorf("MemTotal = %d, want %d", total, want)
	}
	if want := uint64(9000000) * 1024; available != want {
		t.Errorf("MemAvailable = %d, want %d", available, want)
	}
}

func TestParseSizeFieldsProcStatus(t *testing.T) {
	const status = `Name:	go-enclave
Umask:	0022
State:	R (running)
VmPeak:	 2100000 kB
VmSize:	 2000000 kB
VmRSS:	 1234560 kB
VmHWM:	 2045678 kB
RssAnon:	 1200000 kB
Threads:	42
`
	var rss, peak uint64
	parseSizeFields([]byte(status), map[string]*uint64{
		"VmRSS": &rss,
		"VmHWM": &peak,
	})

	if want := uint64(1234560) * 1024; rss != want {
		t.Errorf("VmRSS = %d, want %d", rss, want)
	}
	if want := uint64(2045678) * 1024; peak != want {
		t.Errorf("VmHWM = %d, want %d", peak, want)
	}
}

func TestParseSizeFieldsLeavesBadValuesUntouched(t *testing.T) {
	cases := map[string]string{
		"missing line":  "Name:\tx\nVmSize:\t100 kB\n",
		"empty input":   "",
		"no colon":      "no memtotal here",
		"malformed":     "MemTotal:\tnotanumber kB\n",
		"no value":      "MemTotal:\n",
		"wrong unit":    "MemTotal: 11534336 MB",
		"missing unit":  "MemTotal: 11534336",
		"extra field":   "MemTotal: 11534336 kB extra",
		"overflow":      "MemTotal: 18014398509481984 kB", // > MaxUint64/1024
		"negative":      "MemTotal: -1 kB",
		"lowercase kib": "MemTotal: 11534336 kb",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := uint64(0)
			parseSizeFields([]byte(in), map[string]*uint64{"MemTotal": &got})
			if got != 0 {
				t.Errorf("parseSizeFields(%q) = %d, want 0", in, got)
			}
		})
	}
}

// Keys are matched whole, so a longer field sharing a prefix must not satisfy
// the lookup and report another field's value.
func TestParseSizeFieldsMatchesWholeKeys(t *testing.T) {
	var got uint64
	parseSizeFields([]byte("VmHWMExtra:\t123 kB\n"), map[string]*uint64{"VmHWM": &got})
	if got != 0 {
		t.Errorf("VmHWM = %d, want 0 for a prefix-only match", got)
	}
}

// One bad field must not stop the pass: the remaining requested keys are still
// extracted, so a single malformed line cannot blank the whole reading.
func TestParseSizeFieldsContinuesPastABadField(t *testing.T) {
	const meminfo = `MemTotal:       banana kB
MemAvailable:    9000000 kB
`
	var total, available uint64
	parseSizeFields([]byte(meminfo), map[string]*uint64{
		"MemTotal":     &total,
		"MemAvailable": &available,
	})

	if total != 0 {
		t.Errorf("MemTotal = %d, want 0 for a malformed value", total)
	}
	if want := uint64(9000000) * 1024; available != want {
		t.Errorf("MemAvailable = %d, want %d", available, want)
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
