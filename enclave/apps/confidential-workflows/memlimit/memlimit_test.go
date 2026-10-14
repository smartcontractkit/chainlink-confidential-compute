package memlimit

import "testing"

func TestConcurrency(t *testing.T) {
	cases := []struct {
		name                          string
		totalMB, reserveMB, perExecMB uint64
		want                          int64
	}{
		{"staging 2048 budgets two cold workers", 2048, ReserveMB, PerExecMB, 2},
		{"introspected below 2048 budgets one", 1950, ReserveMB, PerExecMB, 1},
		{"scales up on a 4096 enclave", 4096, ReserveMB, PerExecMB, 6},
		{"reserve exceeds total clamps to 1", 512, ReserveMB, PerExecMB, 1},
		{"total equals reserve clamps to 1", 1024, ReserveMB, PerExecMB, 1},
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

// Derive must never hand back a non-positive limit, which would make the
// semaphore either panic (negative cap) or reject everything (zero). It must
// also report the configured reserve/per-exec so the startup log is accurate.
func TestDerive(t *testing.T) {
	r := Derive()
	if r.MaxConcurrent < 1 {
		t.Fatalf("Derive().MaxConcurrent = %d, want >= 1", r.MaxConcurrent)
	}
	if r.ReserveMB != ReserveMB || r.PerExecMB != PerExecMB {
		t.Fatalf("Derive() = %+v, want ReserveMB=%d PerExecMB=%d", r, ReserveMB, PerExecMB)
	}
}
