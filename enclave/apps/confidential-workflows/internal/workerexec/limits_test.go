package workerexec

import (
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v47"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/stretchr/testify/require"
)

func TestWorkerEnforcesResolvedLimits(t *testing.T) {
	raw, err := wasmtime.Wat2Wasm(`(module
		(import "env" "version_v2" (func))
		(memory (export "memory") 32)
		(func (export "_start")))`)
	require.NoError(t, err)
	job := jobFromWasm(t, raw)
	path := build(t, "../..", "./environments/nitro-worker", "worker", "CGO_ENABLED=1")
	p, err := worker.NewProcesses(path, nil, nil, nil, logger.Test(t))
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		change func(*wasmlimits.Config)
		error  string
	}{
		{"compressed binary", func(c *wasmlimits.Config) { c.MaxCompressedBinary = 1 }, "compressed binary size exceeds"},
		{"decompressed binary", func(c *wasmlimits.Config) { c.MaxDecompressedBinary = 1 }, "decompressed binary size reached"},
		{"linear memory", func(c *wasmlimits.Config) { c.Memory = config.MByte }, "memory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limited := job
			tc.change(&limited.Limits)
			reply, err := p.Run(t.Context(), limited)
			require.NoError(t, err)
			require.NotNil(t, reply.Error)
			require.Contains(t, reply.Error.Error, tc.error)
		})
	}
	reply, err := p.Run(t.Context(), job)
	require.NoError(t, err)
	require.Nil(t, reply.Error, "a new worker with default limits must still succeed")
}
