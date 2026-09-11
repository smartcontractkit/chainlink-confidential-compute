package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type commandCall struct {
	name string
	args []string
}

type recordingCommandRunner struct {
	result commandResult
	err    error
	calls  []commandCall
}

func TestNewNitroCLI(t *testing.T) {
	cli := newNitroCLI()

	assert.Equal(t, defaultNitroCLIBinary, cli.binary)
	assert.IsType(t, execCommandRunner{}, cli.runner)
}

func (r *recordingCommandRunner) Run(_ context.Context, name string, args ...string) (commandResult, error) {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	return r.result, r.err
}

func TestNitroCLIRun(t *testing.T) {
	runner := &recordingCommandRunner{result: commandResult{
		stdout: []byte(`{"EnclaveName":"workflows","EnclaveID":"i-abc-enc123","ProcessID":42,"EnclaveCID":16,"NumberOfCPUs":2,"MemoryMiB":1024}`),
	}}
	cli := newNitroCLIWithRunner("/usr/bin/nitro-cli", runner)

	result, err := cli.Run(context.Background(), nitroRunConfig{
		CPUCount:    2,
		MemoryMiB:   1024,
		EnclaveCID:  16,
		EnclaveName: "workflows",
		EIFPath:     "/home/go-enclave-outbound.eif",
		DebugMode:   true,
	})

	require.NoError(t, err)
	assert.Equal(t, nitroRunResult{EnclaveID: "i-abc-enc123", EnclaveCID: 16}, result)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, commandCall{
		name: "/usr/bin/nitro-cli",
		args: []string{
			"run-enclave",
			"--cpu-count", "2",
			"--memory", "1024",
			"--enclave-cid", "16",
			"--enclave-name", "workflows",
			"--debug-mode",
			"--eif-path", "/home/go-enclave-outbound.eif",
		},
	}, runner.calls[0])
}

func TestNitroCLIRunOmitsOptionalArguments(t *testing.T) {
	runner := &recordingCommandRunner{result: commandResult{
		stdout: []byte(`{"EnclaveID":"i-abc-enc123","EnclaveCID":17}`),
	}}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	_, err := cli.Run(context.Background(), nitroRunConfig{
		CPUCount:  2,
		MemoryMiB: 1024,
		EIFPath:   " /home/go-enclave-outbound.eif ",
	})

	require.NoError(t, err)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{
		"run-enclave",
		"--cpu-count", "2",
		"--memory", "1024",
		"--eif-path", "/home/go-enclave-outbound.eif",
	}, runner.calls[0].args)
}

func TestNitroCLIRunRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config nitroRunConfig
		error  string
	}{
		{
			name:   "zero CPU count",
			config: nitroRunConfig{MemoryMiB: 1024, EIFPath: "/enclave.eif"},
			error:  "CPU count",
		},
		{
			name:   "zero memory",
			config: nitroRunConfig{CPUCount: 2, EIFPath: "/enclave.eif"},
			error:  "memory",
		},
		{
			name:   "empty EIF path",
			config: nitroRunConfig{CPUCount: 2, MemoryMiB: 1024},
			error:  "EIF path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingCommandRunner{}
			cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

			_, err := cli.Run(context.Background(), test.config)

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.error)
			assert.Empty(t, runner.calls)
		})
	}
}

func TestNitroCLIRunRejectsInvalidOutput(t *testing.T) {
	tests := []struct {
		name   string
		result commandResult
		error  string
	}{
		{name: "malformed JSON", result: commandResult{stdout: []byte(`{`)}, error: "decode run-enclave output"},
		{name: "trailing JSON", result: commandResult{stdout: []byte(`{"EnclaveID":"id","EnclaveCID":16} {}`)}, error: "decode run-enclave output"},
		{name: "missing enclave ID", result: commandResult{stdout: []byte(`{"EnclaveCID":16}`)}, error: "missing EnclaveID"},
		{name: "missing enclave CID", result: commandResult{stdout: []byte(`{"EnclaveID":"id"}`)}, error: "missing EnclaveCID"},
		{name: "truncated stdout", result: commandResult{stdout: []byte(`{"EnclaveID":"id"`), stdoutTruncated: true}, error: "output exceeded"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingCommandRunner{result: test.result}
			cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

			_, err := cli.Run(context.Background(), nitroRunConfig{
				CPUCount:  2,
				MemoryMiB: 1024,
				EIFPath:   "/enclave.eif",
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.error)
		})
	}
}

func TestNitroCLIDescribe(t *testing.T) {
	runner := &recordingCommandRunner{result: commandResult{stdout: []byte(`[
		{"EnclaveName":"first","EnclaveID":"i-abc-enc1","EnclaveCID":16,"State":"RUNNING","MemoryMiB":1024},
		{"EnclaveName":"second","EnclaveID":"i-abc-enc2","EnclaveCID":17,"State":"TERMINATING"}
	]`)}}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	result, err := cli.Describe(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []nitroEnclaveDescription{
		{EnclaveName: "first", EnclaveID: "i-abc-enc1", EnclaveCID: 16, State: "RUNNING"},
		{EnclaveName: "second", EnclaveID: "i-abc-enc2", EnclaveCID: 17, State: "TERMINATING"},
	}, result)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, commandCall{name: defaultNitroCLIBinary, args: []string{"describe-enclaves"}}, runner.calls[0])
}

func TestNitroCLIDescribeAllowsEmptyList(t *testing.T) {
	runner := &recordingCommandRunner{result: commandResult{stdout: []byte(`[]`)}}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	result, err := cli.Describe(context.Background())

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestNitroCLIDescribeRejectsNull(t *testing.T) {
	runner := &recordingCommandRunner{result: commandResult{stdout: []byte(`null`)}}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	_, err := cli.Describe(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a JSON array")
}

func TestNitroCLIDescribeRejectsInvalidEntry(t *testing.T) {
	tests := []struct {
		name   string
		output string
		error  string
	}{
		{name: "missing enclave ID", output: `[{"EnclaveCID":16,"State":"RUNNING"}]`, error: "entry 0 missing EnclaveID"},
		{name: "missing state", output: `[{"EnclaveID":"id","EnclaveCID":16}]`, error: "entry 0 missing State"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingCommandRunner{result: commandResult{stdout: []byte(test.output)}}
			cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

			_, err := cli.Describe(context.Background())

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.error)
		})
	}
}

func TestNitroCLITerminate(t *testing.T) {
	runner := &recordingCommandRunner{}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	err := cli.Terminate(context.Background(), " i-abc-enc123 ")

	require.NoError(t, err)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, commandCall{
		name: defaultNitroCLIBinary,
		args: []string{"terminate-enclave", "--enclave-id", "i-abc-enc123"},
	}, runner.calls[0])
}

func TestNitroCLITerminateRejectsEmptyID(t *testing.T) {
	runner := &recordingCommandRunner{}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)

	err := cli.Terminate(context.Background(), " ")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "enclave ID")
	assert.Empty(t, runner.calls)
}

func TestNitroCLICommandErrorIncludesBoundedStderr(t *testing.T) {
	expected := errors.New("exit status 1")
	runner := &recordingCommandRunner{
		result: commandResult{stderr: []byte("allocator exhausted"), stderrTruncated: true},
		err:    expected,
	}
	cli := newNitroCLIWithRunner("/usr/bin/nitro-cli", runner)

	_, err := cli.Describe(context.Background())

	require.ErrorIs(t, err, expected)
	assert.Contains(t, err.Error(), "/usr/bin/nitro-cli describe-enclaves")
	assert.Contains(t, err.Error(), `"allocator exhausted"...truncated`)
}

func TestNitroCLICommandErrorIncludesContextAndStderr(t *testing.T) {
	expected := errors.New("signal: killed")
	runner := &recordingCommandRunner{
		result: commandResult{stderr: []byte("allocator exhausted")},
		err:    expected,
	}
	cli := newNitroCLIWithRunner(defaultNitroCLIBinary, runner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cli.Describe(ctx)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, expected)
	assert.Contains(t, err.Error(), `"allocator exhausted"`)
}

func TestExecCommandRunner(t *testing.T) {
	runner := execCommandRunner{}

	t.Run("captures stdout and stderr", func(t *testing.T) {
		result, err := runner.Run(context.Background(), "/bin/sh", "-c", "printf output; printf diagnostic >&2")

		require.NoError(t, err)
		assert.Equal(t, "output", string(result.stdout))
		assert.Equal(t, "diagnostic", string(result.stderr))
		assert.False(t, result.stdoutTruncated)
		assert.False(t, result.stderrTruncated)
	})

	t.Run("returns command failure", func(t *testing.T) {
		result, err := runner.Run(context.Background(), "/bin/sh", "-c", "printf diagnostic >&2; exit 7")

		require.Error(t, err)
		assert.Equal(t, "diagnostic", string(result.stderr))
	})

	t.Run("bounds stdout", func(t *testing.T) {
		result, err := runner.Run(context.Background(), "/bin/sh", "-c", "printf '%065537d' 0")

		require.NoError(t, err)
		assert.Len(t, result.stdout, maxNitroCLIOutputBytes)
		assert.True(t, result.stdoutTruncated)
	})
}

func TestExecCommandRunnerCancellationIsBounded(t *testing.T) {
	runner := execCommandRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()

	result, err := runner.Run(ctx, "/bin/sh", "-c", "printf diagnostic >&2; sleep 2 & wait")

	require.Error(t, err)
	assert.Less(t, time.Since(started), 1500*time.Millisecond)
	assert.Equal(t, "diagnostic", string(result.stderr))
}

func TestBoundedBuffer(t *testing.T) {
	buffer := newBoundedBuffer(5)

	n, err := buffer.Write([]byte("abcdefgh"))

	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, "abcde", string(buffer.Bytes()))
	assert.True(t, buffer.Truncated())

	n, err = buffer.Write([]byte("ij"))
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, "abcde", string(buffer.Bytes()))
}

func TestBoundedBufferAtLimitIsNotTruncated(t *testing.T) {
	buffer := newBoundedBuffer(5)

	n, err := buffer.Write([]byte("abcde"))

	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "abcde", string(buffer.Bytes()))
	assert.False(t, buffer.Truncated())
}
