package workerexec

import (
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v47"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/stretchr/testify/require"
)

func testWorkerEnforcesResolvedLimits(t *testing.T, workerPath string) {
	raw, err := wasmtime.Wat2Wasm(`(module
		(import "env" "version_v2" (func))
		(memory (export "memory") 32)
		(func (export "_start")))`)
	require.NoError(t, err)
	job := jobFromWasm(t, raw)
	p, err := worker.NewProcesses(workerPath, nil, nil, nil, logger.Test(t))
	require.NoError(t, err)
	limited := job
	limited.Limits.Memory = config.MByte
	reply, err := p.Run(t.Context(), copyJob(t, limited))
	require.NoError(t, err)
	require.NotNil(t, reply.Error)
	require.Contains(t, reply.Error.Error, "memory")
	reply, err = p.Run(t.Context(), copyJob(t, job))
	require.NoError(t, err)
	require.Nil(t, reply.Error, "a new worker with default limits must still succeed")
}
