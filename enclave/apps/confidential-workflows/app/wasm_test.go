package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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
	result, err := executeWasm(t.Context(), logger.Test(t), binary, execReq, false, &enclaveExecutionHelper{})
	require.NoError(t, err)
	require.NotNil(t, result)

	errResult, ok := result.Result.(*sdkpb.ExecutionResult_Value)
	require.True(t, ok, "expected error result, got %T", result.Result)
	assert.Equal(t, "hello from enclave wasm", errResult.Value.GetStringValue())
}
