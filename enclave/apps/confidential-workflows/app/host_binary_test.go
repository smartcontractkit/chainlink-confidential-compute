package app

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/andybalholm/brotli"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// helloBinary builds the test WASM and returns it brotli-compressed with its
// hash, matching what a real WorkflowExecution carries.
func helloBinary(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw := buildTestWasm(t, "hello")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)
	return binary, hash[:]
}

func requireHelloOutput(t *testing.T, output []byte) {
	t.Helper()
	var cwResp confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(output, &cwResp))
	value, ok := cwResp.SdkExecutionResult.Result.(*sdkpb.ExecutionResult_Value)
	require.True(t, ok, "expected value result, got %T", cwResp.SdkExecutionResult.Result)
	assert.Equal(t, "hello from enclave wasm", value.Value.GetStringValue())
}

// The binary arrives as unauthenticatedData from the host; a verified one is
// executed as-is.
func TestExecute_HostBinary_Executes(t *testing.T) {
	binary, hash := helloBinary(t)

	app, locator := newStorageBackedApp(t, binary)
	execution := makeExecution(t, "wf-hello", locator, hash)
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	output, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, binary, nil, emitter.NewNoOpEmitter())
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)
	requireHelloOutput(t, output)
}

// A tampered host binary must never execute: the hash check is the only thing
// standing between the untrusted host and arbitrary code in the TEE.
func TestExecute_HostBinary_TamperedFails(t *testing.T) {
	binary, hash := helloBinary(t)

	app, locator := newStorageBackedApp(t, binary)
	execution := makeExecution(t, "wf-hello", locator, hash)
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	tampered := append([]byte("evil"), binary...)
	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, tampered, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, 502, execErr.Code)
	assert.Contains(t, execErr.Error, "hash mismatch")
}

// An execution without a host binary fails fast: the enclave no longer fetches.
func TestExecute_HostBinary_AbsentFails(t *testing.T) {
	binary, hash := helloBinary(t)

	app, locator := newStorageBackedApp(t, binary)
	execution := makeExecution(t, "wf-hello", locator, hash)
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, 502, execErr.Code)
	assert.Contains(t, execErr.Error, "no workflow binary supplied by the host")
}
