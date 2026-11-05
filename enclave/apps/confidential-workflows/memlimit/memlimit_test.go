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
		{1892, 1, 1},
		{1992, 1, 1},
		{2048, 1, 1},
		{2247, 1, 1},
		{2248, 2, 1},
		{2631, 3, 1},
		{2632, 2, 2}, // Growing the compile pool can lower execution capacity.
		{3000, 3, 2},
		{7071, 9, 7},
		{7072, 8, 8}, // The compile pool reaches its cap.
		{7812, 10, 8},
		{9990, 16, 8},
		{10240, 16, 8},
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
	for _, total := range []uint64{0, 512, 1024, 1100, 1152, 1891} {
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
	for _, total := range []uint64{0, 1100, 1891, 1892, 2631, 2632, 7071, 7072, 7812, 9990, math.MaxUint64} {
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
