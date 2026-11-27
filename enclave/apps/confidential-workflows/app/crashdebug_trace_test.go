package app

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/crashdebug"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestExecuteWritesTraceRecords runs a real workflow with the flight recorder
// on and checks that each phase of the execution reached the ring file, in
// order, which is what the supervisor reads back after a crash.
func TestExecuteWritesTraceRecords(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(crashdebug.EnvCrashDir, dir)
	crashdebug.Init(t.Logf)
	require.True(t, crashdebug.Enabled())

	raw := buildTestWasm(t, "hello")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	app, locator := newStorageBackedApp(t, binary)
	data, err := proto.Marshal(makeExecution(t, "wf-trace", locator, hash[:]))
	require.NoError(t, err)

	requestID := [32]byte{0xab, 0xcd, 0x01}
	_, execErr := app.Execute(requestID, types.AppIDConfidentialWorkflows, data, nil, server.NewResponseEmitter())
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)

	ring, err := os.ReadFile(filepath.Join(dir, crashdebug.TraceRingFile))
	require.NoError(t, err)
	records, err := crashdebug.ReadRing(ring, 0)
	require.NoError(t, err)
	var trace strings.Builder
	for _, rec := range records {
		trace.WriteString(rec.Msg)
		trace.WriteByte('\n')
	}

	t.Logf("trace of one execution:\n%s", trace.String())

	last := -1
	for _, want := range []string{
		"exec rid=abcd010000000000 enter",
		"exec rid=abcd010000000000 validated wf=wf-trace",
		"exec rid=abcd010000000000 grace sleep",
		"exec rid=abcd010000000000 grace done, starting",
		"workflow_execute_started workflow_id=wf-trace",
		"exec rid=abcd010000000000 binary fetch done bytes=",
		"wasm rid=abcd010000000000 compile start binaryBytes=",
		"wasm rid=abcd010000000000 compile done",
		"wasm rid=abcd010000000000 guest execute start",
		"wasm rid=abcd010000000000 guest execute done",
		"wasm rid=abcd010000000000 module close done",
		"exec rid=abcd010000000000 return ok outputBytes=",
	} {
		at := strings.Index(trace.String(), want)
		require.GreaterOrEqual(t, at, 0, "missing %q in trace:\n%s", want, trace.String())
		require.Greater(t, at, last, "%q is out of order in trace:\n%s", want, trace.String())
		last = at
	}
}
