package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
)

func TestExecuteWasm_CompilationQueueOverlappingGuests(t *testing.T) {
	binary := buildTestWasm(t, "http-call")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ctx = contexts.WithCRE(ctx, contexts.CRE{Org: "org", Owner: "owner", Workflow: "workflow"})
	guest, release := context.WithCancel(ctx)
	helper := queuedExecutionHelper{
		enclaveExecutionHelper: &enclaveExecutionHelper{},
		entered:                make(chan context.Context, 2),
		release:                guest.Done(),
	}
	slot := semaphore.NewWeighted(1)
	done := make(chan error, 2)
	var wg sync.WaitGroup
	defer func() { release(); wg.Wait() }()
	for range 2 {
		// The WASM host writes to the request, so each guest needs its own.
		req := makeExecution(t, "workflow", "unused", nil).SdkExecuteRequest
		wg.Go(func() {
			_, err := executeWasm(ctx, logger.Test(t), emitter.NewNoOpEmitter(), slot, binary, req, false, helper, time.Minute)
			done <- err
		})
	}
	for range 2 {
		select {
		case <-helper.entered:
		case err := <-done:
			t.Fatalf("guest finished before both executions overlapped: %v", err)
		case <-ctx.Done():
			t.Fatal("compilation queue serialized guest execution")
		}
	}
	release()
	for range 2 {
		require.NoError(t, <-done)
	}
}

func TestExecute_CompilationQueueRetainsAdmissionUntilFailure(t *testing.T) {
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write([]byte("invalid wasm"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)
	budget, err := memlimit.ForMemory(2248) // Two executions sharing one compile slot.
	require.NoError(t, err)
	require.Equal(t, int64(2), budget.MaxConcurrentExecutions)
	require.Equal(t, int64(1), budget.MaxConcurrentCompilations)
	lggr, _ := logger.TestObserved(t, zapcore.DebugLevel)
	enclave, err := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, lggr, Config{
		MaxConcurrentExecutions: budget.MaxConcurrentExecutions,
		CompileCapacity:         budget.MaxConcurrentCompilations,
		HTTPFetcher:             httpfetch.NewFetcher(httpfetch.DefaultPolicy()),
		StorageFetcherFactory: storageFetcherFactory(func() types.HTTPClient {
			return util.NewUnrestrictedClient()
		}),
		RemoteDispatcherFactory: func(GatewayConfig) (RemoteDispatcher, error) {
			return &testRemoteDispatcher{}, nil
		},
	})
	require.NoError(t, err)
	a := enclave.(*confidentialWorkflowsApp)
	settings := testSettings(startFakeStorage(t, binary))
	settings.WorkflowGracePeriod = Duration(-time.Second)
	settings.MaxConcurrentCompilations = 8
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, a.InjectSettings(raw))
	t.Cleanup(func() { require.NoError(t, a.storageFetcher.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	// Finish downloading before reinjection closes the old storage connection.
	_, err = a.fetcher.Fetch(ctx, testLocator, hash[:], a.storageFetcher)
	require.NoError(t, err)
	compileSlot := a.compileSlots.Load()
	require.NoError(t, compileSlot.Acquire(ctx, 1))
	release := sync.OnceFunc(func() { compileSlot.Release(1) })
	results := make(chan *types.ExecuteError, 2)
	var wg sync.WaitGroup
	defer func() { release(); wg.Wait() }()
	require.False(t, compileSlot.TryAcquire(1), "requested concurrency must be capped to one permit")
	for i := range 2 {
		input, err := proto.Marshal(makeExecution(t, fmt.Sprintf("workflow-%d", i), testLocator, hash[:]))
		require.NoError(t, err)
		wg.Go(func() {
			_, err := a.Execute([32]byte{byte(i)}, types.AppIDConfidentialWorkflows, input, nil, emitter.NewNoOpEmitter())
			results <- err
		})
	}
	require.Eventually(t, func() bool { return len(a.limiter.slots) == 2 }, 5*time.Second, time.Millisecond)
	_, rejected := a.Execute([32]byte{3}, types.AppIDConfidentialWorkflows, nil, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, rejected)
	require.Equal(t, http.StatusTooManyRequests, rejected.Code)
	select {
	case result := <-results:
		t.Fatalf("execution bypassed occupied compilation queue: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, a.InjectSettings(raw))
	require.True(t, compileSlot == a.compileSlots.Load(), "reinjection must reuse the compilation gate")
	require.False(t, a.compileSlots.Load().TryAcquire(1), "reinjection must not add permits")
	release()
	for range 2 {
		select {
		case result := <-results:
			require.NotNil(t, result)
			require.Contains(t, result.Error, "creating wasm module")
		case <-ctx.Done():
			t.Fatal("failed compilation did not release the queue")
		}
	}
	require.Empty(t, a.limiter.slots)
	require.True(t, compileSlot.TryAcquire(1))
	compileSlot.Release(1)
}
