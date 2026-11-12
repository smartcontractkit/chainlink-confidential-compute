package nitro

import (
	"errors"
	"io"
	"io/fs"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClockSource(t *testing.T) {
	tests := []struct {
		name         string
		architecture string
		source       string
		wantError    bool
	}{
		{name: "x86 KVM clock", architecture: "amd64", source: "kvm-clock"},
		{name: "ARM architected counter", architecture: "arm64", source: "arch_sys_counter"},
		{name: "x86 rejects ARM clock", architecture: "amd64", source: "arch_sys_counter", wantError: true},
		{name: "ARM rejects x86 clock", architecture: "arm64", source: "kvm-clock", wantError: true},
		{name: "x86 rejects TSC", architecture: "amd64", source: "tsc", wantError: true},
		{name: "ARM rejects fallback clock", architecture: "arm64", source: "jiffies", wantError: true},
		{name: "empty clock", architecture: "arm64", wantError: true},
		{name: "read failure", architecture: "arm64", source: "error reading clock source: permission denied", wantError: true},
		{name: "unsupported architecture", architecture: "386", source: "kvm-clock", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClockSource(tt.architecture, tt.source)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateClockSource(%q, %q) = %v, wantError %t", tt.architecture, tt.source, err, tt.wantError)
			}
		})
	}
}

func TestVerifyEnvironment_RetriesTransientFailures(t *testing.T) {
	calls := 0
	checks := []environmentCheck{{"chrony", func() error {
		calls++
		if calls < 3 {
			return errors.New("not synced yet")
		}
		return nil
	}}}

	require.NoError(t, verifyEnvironment(log.New(io.Discard, "", 0), checks, 5, 0))
	assert.Equal(t, 3, calls)
}

func TestVerifyEnvironment_FailsAfterBoundedAttempts(t *testing.T) {
	calls, laterCalls := 0, 0
	checks := []environmentCheck{
		{"clock source", func() error {
			calls++
			return errors.New("invalid clock source: tsc")
		}},
		{"later", func() error {
			laterCalls++
			return nil
		}},
	}

	err := verifyEnvironment(log.New(io.Discard, "", 0), checks, 4, 0)
	require.ErrorContains(t, err, "clock source check failed after 4 attempts: invalid clock source: tsc")
	assert.Equal(t, 4, calls)
	assert.Zero(t, laterCalls, "checks after a failed gate must not run")
}

// A failure to read the parent-instance state must be distinguishable from
// the state being wrong.
func TestCheckClockSource(t *testing.T) {
	read := func(data string, err error) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(data), err }
	}
	require.NoError(t, checkClockSource("amd64", read("kvm-clock\n", nil)))
	require.EqualError(t, checkClockSource("amd64", read("tsc\n", nil)), "invalid clock source for amd64: tsc, want kvm-clock")

	err := checkClockSource("amd64", read("", fs.ErrNotExist))
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorContains(t, err, "reading clock source")
}

func TestCheckChronySources(t *testing.T) {
	const synced = "MS Name/IP address         Stratum Poll Reach LastRx Last sample\n#* PHC0                          0   2   377     5    +12ns[  +15ns] +/-  110ns\n"
	const unsynced = "MS Name/IP address         Stratum Poll Reach LastRx Last sample\n#? PHC0                          0   2     1     5    +12ns[  +15ns] +/-  110ns\n"
	sources := func(output string, err error) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(output), err }
	}
	require.NoError(t, checkChronySources(sources(synced, nil)))
	require.ErrorContains(t, checkChronySources(sources(unsynced, nil)), "invalid PTP time synchronization source")

	errChronyd := errors.New("506 Cannot talk to daemon")
	err := checkChronySources(sources("", errChronyd))
	require.ErrorIs(t, err, errChronyd)
	require.ErrorContains(t, err, "running chronyc sources")
}
