package server

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestCPUSecondsFromRusage(t *testing.T) {
	tests := []struct {
		name   string
		user   unix.Timeval
		system unix.Timeval
		want   uint64
	}{
		{name: "below rounding boundary", user: unix.Timeval{Usec: 499_999}, want: 0},
		{name: "at rounding boundary", user: unix.Timeval{Usec: 500_000}, want: 1},
		{name: "below next boundary", user: unix.Timeval{Sec: 1, Usec: 499_999}, want: 1},
		{name: "at next boundary", user: unix.Timeval{Sec: 1, Usec: 500_000}, want: 2},
		{
			name:   "combines user and system time",
			user:   unix.Timeval{Usec: 600_000},
			system: unix.Timeval{Usec: 600_000},
			want:   1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, cpuSecondsFromRusage(test.user, test.system))
		})
	}
}

func TestParseGuestCPUTicks(t *testing.T) {
	tests := []struct {
		name      string
		stat      string
		wantBusy  uint64
		wantTotal uint64
		wantOK    bool
	}{
		{
			name:      "aggregate with guest fields",
			stat:      "cpu0 9999 0 0 0 0 0 0 0\ncpu  100 20 30 1000 50 10 5 2 500 10\ncpu1 9999 0 0 0 0 0 0 0\n",
			wantBusy:  165,
			wantTotal: 1217,
			wantOK:    true,
		},
		{name: "missing aggregate", stat: "cpu0 1 2 3 4 5 6 7 8\n"},
		{name: "too few fields", stat: "cpu  1 2 3 4 5 6 7\n"},
		{name: "non-numeric", stat: "cpu  1 2 3 4 5 nope 7 8\n"},
		{name: "negative", stat: "cpu  1 2 3 4 5 -1 7 8\n"},
		{name: "busy overflow", stat: "cpu  18446744073709551615 1 0 0 0 0 0 0\n"},
		{name: "total overflow", stat: "cpu  18446744073709551615 0 0 1 0 0 0 0\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			busy, total, ok := parseGuestCPUTicks([]byte(test.stat))
			assert.Equal(t, test.wantOK, ok)
			assert.Equal(t, test.wantBusy, busy)
			assert.Equal(t, test.wantTotal, total)
		})
	}
}

func TestCPUTicksToSeconds(t *testing.T) {
	tests := []struct {
		name  string
		ticks uint64
		want  uint64
	}{
		{name: "zero", ticks: 0, want: 0},
		{name: "below rounding boundary", ticks: 49, want: 0},
		{name: "at rounding boundary", ticks: 50, want: 1},
		{name: "below next boundary", ticks: 149, want: 1},
		{name: "at next boundary", ticks: 150, want: 2},
		{name: "maximum without overflow", ticks: math.MaxUint64, want: 184467440737095516},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, cpuTicksToSeconds(test.ticks))
		})
	}
}
