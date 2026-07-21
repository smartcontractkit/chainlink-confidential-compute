package memlimit

import "testing"

func TestConcurrency(t *testing.T) {
	cases := []struct {
		name                          string
		totalMB, reserveMB, perExecMB uint64
		want                          int64
	}{
		{"staging 2048 reproduces default 8", 2048, 1024, 128, 8},
		{"introspected below 2048 stays close", 1950, 1024, 128, 7},
		{"scales up on a 4096 enclave", 4096, 1024, 128, 24},
		{"reserve exceeds total clamps to 1", 512, 1024, 128, 1},
		{"total equals reserve clamps to 1", 1024, 1024, 128, 1},
		{"zero per-exec clamps to 1", 2048, 1024, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := concurrency(tc.totalMB, tc.reserveMB, tc.perExecMB); got != tc.want {
				t.Fatalf("concurrency(%d, %d, %d) = %d, want %d",
					tc.totalMB, tc.reserveMB, tc.perExecMB, got, tc.want)
			}
		})
	}
}

// MaxConcurrentExecutions must never hand back a non-positive limit, which would
// make the semaphore either panic (negative cap) or reject everything (zero).
func TestMaxConcurrentExecutionsIsPositive(t *testing.T) {
	if got := MaxConcurrentExecutions(); got < 1 {
		t.Fatalf("MaxConcurrentExecutions() = %d, want >= 1", got)
	}
}
