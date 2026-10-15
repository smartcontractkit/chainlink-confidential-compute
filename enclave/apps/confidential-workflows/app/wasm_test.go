package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
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
	result, err := executeWasm(ctx, logger.Test(t), semaphore.NewWeighted(1), nil, binary, execReq, false, &enclaveExecutionHelper{}, 0)
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
	result, err := executeWasm(ctx, logger.Test(t), semaphore.NewWeighted(1), nil, binary, execReq, false, &enclaveExecutionHelper{}, time.Second)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, result)
	assert.Less(t, time.Since(start), 30*time.Second, "the epoch deadline should interrupt the guest promptly")
}

type queuedExecutionHelper struct {
	*enclaveExecutionHelper
	entered chan context.Context
	release <-chan struct{}
}

func (h queuedExecutionHelper) CallCapability(ctx context.Context, _ *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	h.entered <- ctx
	<-h.release
	return nil, errors.New("test capability stopped")
}

func TestExecuteWasm_CompilationQueue(t *testing.T) {
	binary := buildTestWasm(t, "http-call")
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	req := &sdkpb.ExecuteRequest{Request: &sdkpb.ExecuteRequest_Trigger{
		Trigger: &sdkpb.Trigger{Id: 0, Payload: payload},
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ctx = contexts.WithCRE(ctx, contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	slot := semaphore.NewWeighted(1)
	require.NoError(t, slot.Acquire(ctx, 1))
	guest, releaseGuest := context.WithCancel(ctx)
	defer releaseGuest()
	helper := queuedExecutionHelper{enclaveExecutionHelper: &enclaveExecutionHelper{}, entered: make(chan context.Context, 1), release: guest.Done()}
	done := make(chan error, 1)
	const budget = 30 * time.Second
	go func() {
		_, err := executeWasm(ctx, logger.Test(t), slot, nil, binary, req, false, helper, budget)
		done <- err
	}()
	select {
	case <-helper.entered:
		t.Fatal("execution bypassed the occupied compilation slot")
	case err := <-done:
		t.Fatalf("execution bypassed the occupied compilation slot: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	released := time.Now()
	slot.Release(1)
	select {
	case executionCtx := <-helper.entered:
		deadline, ok := executionCtx.Deadline()
		require.True(t, ok)
		require.False(t, deadline.Before(released.Add(budget)), "queue wait must not consume the execution budget")
	case err := <-done:
		t.Fatalf("execution did not reach the capability: %v", err)
	case <-ctx.Done():
		t.Fatal("execution did not leave the compilation queue")
	}
	require.True(t, slot.TryAcquire(1), "guest execution must not hold the compilation slot")
	slot.Release(1)
	releaseGuest()
	require.NoError(t, <-done)
	_, err = executeWasm(ctx, logger.Test(t), slot, nil, []byte("invalid wasm"), req, false, &enclaveExecutionHelper{}, 0)
	require.Error(t, err)
	require.True(t, slot.TryAcquire(1), "failed compilation must release the slot")
}
