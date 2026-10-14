package wasmruntime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bytecodealliance/wasmtime-go/v47"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func testLimits() wasmlimits.Config {
	return wasmlimits.Config{
		Memory: 16 * config.MByte, MaxCompressedBinary: config.MByte, MaxDecompressedBinary: config.MByte,
		MaxResponseSize: config.MByte, PendingCalls: 10, MaxSubscriptions: 100,
	}
}

func compiledFixture(t *testing.T, body string) []byte {
	t.Helper()
	raw, err := wasmtime.Wat2Wasm(`(module (import "env" "version_v2" (func))
 (memory (export "memory") 1) (func (export "_start") ` + body + `))`)
	require.NoError(t, err)
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, err = w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func newTestCompiler(t *testing.T) *Compiler {
	t.Helper()
	c, err := NewCompiler(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

type inspectingHelper struct {
	host.ExecutionHelper
	inspect func()
}

func (h inspectingHelper) GetWorkflowExecutionID() string { h.inspect(); return "id" }

func TestCompileAndLoadPrivateArtifacts(t *testing.T) {
	c := newTestCompiler(t)
	lggr, logs := logger.TestObserved(t, zapcore.InfoLevel)
	binary := compiledFixture(t, "unreachable")
	info, err := os.Stat(c.dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	first, err := c.Compile(t.Context(), lggr, testLimits(), binary, 0)
	require.NoError(t, err, "compilation must not execute the trapping guest")
	require.True(t, first.Deadline.IsZero())
	second, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.NoError(t, err)
	require.NotEqual(t, first.Path, second.Path)
	info, err = os.Stat(first.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	inspected := false
	_, err = Execute(t.Context(), lggr, testLimits(), first.Path, &sdkpb.ExecuteRequest{}, inspectingHelper{inspect: func() {
		_, err := os.Stat(first.Path)
		require.ErrorIs(t, err, os.ErrNotExist, "unlink must precede execution")
		inspected = true
	}})
	require.ErrorContains(t, err, "unreachable")
	require.True(t, inspected)
	compiled := logs.FilterMessage("workflow compilation completed").All()
	require.Len(t, compiled, 1)
	require.Contains(t, compiled[0].ContextMap(), "queueDuration")
	require.Contains(t, compiled[0].ContextMap(), "duration")
	loaded := logs.FilterMessage("workflow artifact loaded").All()
	require.Len(t, loaded, 1)
	require.Contains(t, loaded[0].ContextMap(), "duration")
	RemoveArtifact(logger.Test(t), first.Path)
	RemoveArtifact(logger.Test(t), second.Path)
	entries, err := os.ReadDir(c.dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestCompilerUsesExplicitDirectory(t *testing.T) {
	base := t.TempDir()
	binary := compiledFixture(t, "")
	t.Setenv("TMPDIR", filepath.Join(base, "missing-temp-dir"))
	c, err := NewCompiler(base)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	require.Equal(t, base, filepath.Dir(c.dir))
	prepared, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.NoError(t, err)
	_, err = Execute(t.Context(), logger.Test(t), testLimits(), prepared.Path, &sdkpb.ExecuteRequest{}, inspectingHelper{inspect: func() {}})
	require.NoError(t, err)
}

func TestArtifactNamesAreNotReusedAfterUnlink(t *testing.T) {
	c := newTestCompiler(t)
	binary := compiledFixture(t, "")
	first, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.NoError(t, err)
	require.Regexp(t, `^module-1-`, filepath.Base(first.Path))
	RemoveArtifact(logger.Test(t), first.Path)
	second, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.NoError(t, err)
	require.Regexp(t, `^module-2-`, filepath.Base(second.Path))
	RemoveArtifact(logger.Test(t), first.Path)
	_, err = os.Stat(second.Path)
	require.NoError(t, err, "retrying old cleanup must leave the new artifact intact")
}

func TestCompileLimitsAndFailureCleanup(t *testing.T) {
	c := newTestCompiler(t)
	binary := compiledFixture(t, "")
	for _, tc := range []struct {
		name   string
		change func(*wasmlimits.Config)
		want   string
	}{
		{"compressed", func(v *wasmlimits.Config) { v.MaxCompressedBinary = 1 }, "compressed binary size exceeds"},
		{"decompressed", func(v *wasmlimits.Config) { v.MaxDecompressedBinary = 1 }, "decompressed binary size reached"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := testLimits()
			tc.change(&limits)
			_, err := c.Compile(t.Context(), logger.Test(t), limits, binary, 0)
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, c.slot)
			entries, err := os.ReadDir(c.dir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
	_, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, time.Nanosecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, c.slot)
	entries, err := os.ReadDir(c.dir)
	require.NoError(t, err)
	require.Empty(t, entries)

	require.NoError(t, os.Remove(c.dir))
	_, err = c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.ErrorContains(t, err, "creating compiled artifact")
	require.Empty(t, c.slot)
	require.NoError(t, os.Mkdir(c.dir, 0700))
	_, err = c.Compile(t.Context(), logger.Test(t), testLimits(), binary, 0)
	require.NoError(t, err, "a failed preparation must release the compilation slot")
}

type blockingCompileLogger struct {
	logger.Logger
	completed chan struct{}
	release   chan struct{}
}

func (l blockingCompileLogger) Infow(string, ...any) {
	close(l.completed)
	<-l.release
}

func TestCompilerSlotAndTimeoutAccounting(t *testing.T) {
	c := newTestCompiler(t)
	binary := compiledFixture(t, "")
	lggr := blockingCompileLogger{Logger: logger.Test(t), completed: make(chan struct{}), release: make(chan struct{})}
	first := make(chan error, 1)
	go func() { _, err := c.Compile(t.Context(), lggr, testLimits(), binary, 0); first <- err }()
	<-lggr.completed
	require.Len(t, c.slot, 1, "slot remains held after native cleanup")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.Compile(ctx, logger.Test(t), testLimits(), binary, time.Second)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, c.slot, 1, "a canceled waiter must not release another compilation's slot")

	done := make(chan PreparedArtifact, 1)
	errs := make(chan error, 1)
	const budget = 10 * time.Second
	go func() {
		prepared, err := c.Compile(t.Context(), logger.Test(t), testLimits(), binary, budget)
		done <- prepared
		errs <- err
	}()
	select {
	case <-done:
		t.Fatal("second compilation bypassed the occupied slot")
	case <-time.After(150 * time.Millisecond):
	}
	released := time.Now()
	close(lggr.release)
	require.NoError(t, <-first)
	prepared := <-done
	require.NoError(t, <-errs, "queue wait must not consume the execution budget")
	require.False(t, prepared.Deadline.Before(released.Add(budget)))
}

func TestSerializedLoadFailureRemovesArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	require.NoError(t, os.WriteFile(path, []byte("not a native artifact"), 0600))
	_, err := Execute(t.Context(), logger.Test(t), testLimits(), path, nil, nil)
	require.ErrorContains(t, err, "loading wasm module")
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRemoveArtifactFailureOnlyWarns(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "child"), nil, 0600))
	RemoveArtifact(lggr, dir)
	require.Len(t, logs.All(), 1)
	require.Equal(t, "cannot remove compiled workflow artifact", logs.All()[0].Message)
}

func TestApplyExecutionDeadline(t *testing.T) {
	normal, prehook := 10*time.Minute, 10*time.Second
	cfg := &host.ModuleConfig{Timeout: &normal, PrehookTimeout: &prehook}
	require.NoError(t, applyExecutionDeadline(t.Context(), cfg))
	require.Same(t, &normal, cfg.Timeout)
	for _, budget := range []time.Duration{time.Second, time.Minute} {
		ctx, cancel := context.WithTimeout(t.Context(), budget)
		require.NoError(t, applyExecutionDeadline(ctx, cfg))
		cancel()
		require.Positive(t, *cfg.Timeout)
		require.LessOrEqual(t, *cfg.Timeout, budget)
		require.LessOrEqual(t, *cfg.PrehookTimeout, 10*time.Second)
		require.LessOrEqual(t, *cfg.PrehookTimeout, budget)
		require.Equal(t, 10*time.Minute, normal)
		require.Equal(t, 10*time.Second, prehook)
		cfg.PrehookTimeout = &prehook
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	require.ErrorIs(t, applyExecutionDeadline(ctx, cfg), context.DeadlineExceeded)
}
