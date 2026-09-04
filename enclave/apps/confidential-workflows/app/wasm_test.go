package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

// buildTestWasm compiles a WASM binary from the given testdata subdirectory.
func buildTestWasm(t *testing.T, name string) []byte {
	t.Helper()

	srcDir, err := filepath.Abs(filepath.Join("testdata", name))
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), name+".wasm")
	cmd := exec.Command("go", "build", "-o", outFile, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to compile test wasm: %s", string(output))

	binary, err := os.ReadFile(outFile)
	require.NoError(t, err)
	return binary
}

func TestExecuteWasm_Hello(t *testing.T) {
	binary := buildTestWasm(t, "hello")

	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execReq := &sdkpb.ExecuteRequest{
		Request: &sdkpb.ExecuteRequest_Trigger{
			Trigger: &sdkpb.Trigger{Id: 0, Payload: payload},
		},
	}
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	result, err := executeWasm(ctx, limits.Factory{Logger: logger.Test(t)}, binary, execReq, false, &enclaveExecutionHelper{}, 0)
	require.NoError(t, err)
	require.NotNil(t, result)

	errResult, ok := result.Result.(*sdkpb.ExecutionResult_Value)
	require.True(t, ok, "expected error result, got %T", result.Result)
	assert.Equal(t, "hello from enclave wasm", errResult.Value.GetStringValue())
}

// A workflow spinning in pure compute makes no host calls, so the module
// timeout (wasmtime epoch deadline) is the only thing that can stop it. The
// WASM host reports that as context.DeadlineExceeded.
func TestExecuteWasm_Timeout(t *testing.T) {
	binary := buildTestWasm(t, "spin")

	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execReq := &sdkpb.ExecuteRequest{
		Request: &sdkpb.ExecuteRequest_Trigger{
			Trigger: &sdkpb.Trigger{Id: 0, Payload: payload},
		},
	}

	start := time.Now()
	ctx := contexts.WithCRE(t.Context(), contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	result, err := executeWasm(ctx, limits.Factory{Logger: logger.Test(t)}, binary, execReq, false, &enclaveExecutionHelper{}, time.Second)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, result)
	assert.Less(t, time.Since(start), 30*time.Second, "the epoch deadline should interrupt the guest promptly")
}
