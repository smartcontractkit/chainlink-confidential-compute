package memlimit

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForMemory(t *testing.T) {
	cases := []struct {
		total                    uint64
		executions, compilations int64
	}{
		{1664, 1, 1},
		{1992, 3, 1},
		{2048, 4, 1},
		{1791, 1, 1},
		{1792, 2, 1},
		{2175, 4, 1},
		{2176, 2, 2}, // Growing the compile pool can lower execution capacity.
		{3000, 5, 3},
		{5247, 10, 7},
		{5248, 8, 8}, // The compile pool reaches its cap.
		{5504, 10, 8},
		{9990, 45, 8},
		{10240, 47, 8},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.total), func(t *testing.T) {
			r, err := ForMemory(tc.total)
			require.NoError(t, err)
			require.Equal(t, tc.executions, r.MaxConcurrentExecutions)
			require.Equal(t, tc.compilations, r.MaxConcurrentCompilations)
			require.Equal(t, tc.total, r.TotalMB)
			require.Equal(t, ReserveMB, r.ReserveMB)
			require.Equal(t, SafetyMB, r.SafetyMB)
			require.Equal(t, PerExecMB, r.PerExecMB)
			require.Equal(t, PerCompilationMB, r.PerCompilationMB)
		})
	}
	for _, total := range []uint64{0, 512, 1024, 1100, 1152, 1663} {
		_, err := ForMemory(total)
		require.Error(t, err, "total=%d", total)
	}
}

func TestDerive(t *testing.T) {
	total, readErr := totalMemoryMB()
	got, err := Derive()
	if readErr != nil {
		require.ErrorContains(t, err, "reading guest memory")
		require.Zero(t, got)
		return
	}
	want, budgetErr := ForMemory(total)
	if budgetErr != nil {
		require.EqualError(t, err, budgetErr.Error())
	} else {
		require.NoError(t, err)
	}
	require.Equal(t, want, got)
}

func FuzzForMemory(f *testing.F) {
	for _, total := range []uint64{0, 1100, 1663, 1664, 2175, 2176, 5247, 5248, 5504, 9990, math.MaxUint64} {
		f.Add(total)
	}
	f.Fuzz(func(t *testing.T, total uint64) {
		r, err := ForMemory(total)
		if total < ReserveMB+SafetyMB+PerExecMB+PerCompilationMB {
			require.Error(t, err)
		} else if (total-ReserveMB-SafetyMB)/PerExecMB <= uint64(math.MaxInt) {
			// Even without reserving compilation memory, the execution count fits.
			require.NoError(t, err)
		}
		if err != nil {
			return
		}
		require.Positive(t, r.MaxConcurrentCompilations)
		require.GreaterOrEqual(t, r.MaxConcurrentExecutions, r.MaxConcurrentCompilations)
		require.LessOrEqual(t, uint64(r.MaxConcurrentCompilations), TargetCompilations)
		require.LessOrEqual(t, ReserveMB+SafetyMB, total)
		available := total - ReserveMB - SafetyMB
		require.LessOrEqual(t, uint64(r.MaxConcurrentCompilations), available/PerCompilationMB)
		available -= uint64(r.MaxConcurrentCompilations) * PerCompilationMB
		require.Equal(t, available/PerExecMB, uint64(r.MaxConcurrentExecutions))
	})
}
