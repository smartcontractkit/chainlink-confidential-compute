package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/andybalholm/brotli"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basicaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/proto"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	httpserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http/server"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
)

// makeExecution builds a WorkflowExecution with a trigger ExecuteRequest baked in.
func makeExecution(t *testing.T, workflowID, binaryURL string, binaryHash []byte) *confworkflowtypes.WorkflowExecution {
	t.Helper()
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	return &confworkflowtypes.WorkflowExecution{
		WorkflowId: workflowID,
		BinaryUrl:  binaryURL,
		BinaryHash: binaryHash,
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Request: &sdkpb.ExecuteRequest_Trigger{
				Trigger: &sdkpb.Trigger{Id: 0, Payload: payload},
			},
		},
	}
}

func TestNewConfidentialWorkflowsAppRequiresProductionTransports(t *testing.T) {
	valid := Config{
		HTTPFetcher: httpfetch.NewFetcherWithClient(httpfetch.DefaultPolicy(), util.NewUnrestrictedClient()),
		StorageFetcherFactory: storageFetcherFactory(func() types.HTTPClient {
			return util.NewUnrestrictedClient()
		}),
		RemoteDispatcherFactory: func(GatewayConfig) (RemoteDispatcher, error) {
			return &testRemoteDispatcher{}, nil
		},
	}

	tests := map[string]func(*Config){
		"HTTP fetcher":              func(c *Config) { c.HTTPFetcher = nil },
		"storage fetcher factory":   func(c *Config) { c.StorageFetcherFactory = nil },
		"remote dispatcher factory": func(c *Config) { c.RemoteDispatcherFactory = nil },
		"negative compile capacity": func(c *Config) { c.CompileCapacity = -1 },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			remove(&config)
			_, err := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), config)
			require.Error(t, err)
		})
	}

	_, err := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), valid)
	require.NoError(t, err)
}

func TestExecute_HelloWasm(t *testing.T) {
	// Build the test WASM binary, brotli-compress it, and serve over HTTP.
	raw := buildTestWasm(t, "hello")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	app, locator := newStorageBackedApp(t, binary)
	execution := makeExecution(t, "wf-hello", locator, hash[:])
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	output, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)

	var cwResp confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(output, &cwResp))
	require.NotEmpty(t, cwResp.SdkExecutionResult, "execution_result should not be empty")

	errResult, ok := cwResp.SdkExecutionResult.Result.(*sdkpb.ExecutionResult_Value)
	require.True(t, ok, "expected value result, got %T", cwResp.SdkExecutionResult.Result)
	assert.Equal(t, "hello from enclave wasm", errResult.Value.GetStringValue())
}

// TestExecute_HttpCallWasm is the WASM-level integration test for the
// in-enclave http-actions shortcircuit (tier 2 of execution_helper.go).
// It compiles the http-call WASM, runs it through cwapp.Execute, and asserts
// the workflow's http-actions call reaches a loopback echo server via the
// injected httpfetch.Fetcher rather than the remote dispatcher.
func TestExecute_HttpCallWasm(t *testing.T) {
	// 1. Start an echo HTTP server that returns the request body.
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp := map[string]string{"body": string(body)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer echoSrv.Close()

	// 2. Build the http-call WASM binary, brotli-compress, and serve over HTTP.
	raw := buildTestWasm(t, "http-call")
	var compressed bytes.Buffer
	bw := brotli.NewWriter(&compressed)
	_, err := bw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	// 3. Build ExecuteRequest with Config = echo server URL.
	triggerPayload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execReq := &sdkpb.ExecuteRequest{
		Config: []byte(echoSrv.URL),
		Request: &sdkpb.ExecuteRequest_Trigger{
			Trigger: &sdkpb.Trigger{Id: 0, Payload: triggerPayload},
		},
	}

	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId:        "wf-http-call",
		BinaryUrl:         testLocator,
		BinaryHash:        hash[:],
		SdkExecuteRequest: execReq,
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	// 4. Inject a permissive httpfetch.Fetcher so the WASM's http-actions call
	//    is shortcircuited locally (tier 2 of execution_helper.go) and reaches
	//    the loopback echo server. No remote dispatcher needed: the
	//    shortcircuit handles SendRequest entirely in-process.
	// Inject an unrestricted client so the fetcher can reach the loopback echo
	// server the restricted client would block.
	fetcher := httpfetch.NewFetcherWithClient(httpfetch.Policy{
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		DefaultTimeout:       5 * time.Second,
		MaxResponseBodyBytes: 10 << 20,
	}, util.NewUnrestrictedClient())

	app, _ := newStorageBackedApp(t, binary, WithHTTPFetcher(fetcher))
	output, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)

	// 5. Unwrap ConfidentialWorkflowResponse -> ExecutionResult -> Value.
	var cwResp confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(output, &cwResp))
	require.NotEmpty(t, cwResp.SdkExecutionResult, "execution_result should not be empty")

	valResult, ok := cwResp.SdkExecutionResult.Result.(*sdkpb.ExecutionResult_Value)
	require.True(t, ok, "expected Value result, got %T", cwResp.SdkExecutionResult.Result)

	val, err := values.FromProto(valResult.Value)
	require.NoError(t, err)
	unwrapped, err := val.Unwrap()
	require.NoError(t, err)

	resultMap, ok := unwrapped.(map[string]any)
	require.True(t, ok, "expected map, got %T", unwrapped)

	// 6. Validate: WASM returned status 200, and the echo server saw our body.
	assert.Equal(t, int64(200), resultMap["StatusCode"], "expected status 200")

	bodyStr, ok := resultMap["Body"].(string)
	require.True(t, ok, "body should be a string")

	var echoResp map[string]string
	require.NoError(t, json.Unmarshal([]byte(bodyStr), &echoResp), fmt.Sprintf("echo response: %s", bodyStr))
	assert.Equal(t, "hello from wasm", echoResp["body"])
}

// End-to-end proof that a per-capability metric flows all the way through:
// app.Execute -> WASM host -> guest calls SendRequest -> helper.CallCapability
// -> emitter.Emit -> captured. Same http-call harness as TestExecute_HttpCallWasm,
// but with a recording emitter instead of the no-op.
func TestExecute_HttpCallWasm_EmitsCapabilityMetric(t *testing.T) {
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"body": string(body)})
	}))
	defer echoSrv.Close()

	raw := buildTestWasm(t, "http-call")
	var compressed bytes.Buffer
	bw := brotli.NewWriter(&compressed)
	_, err := bw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	triggerPayload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId: "wf-http-call",
		BinaryUrl:  testLocator,
		BinaryHash: hash[:],
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Config:  []byte(echoSrv.URL),
			Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: triggerPayload}},
		},
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	app, _ := newStorageBackedApp(t, binary, WithHTTPFetcher(permissiveFetcher()))

	em := &recordingEmitter{}
	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, em)
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)

	require.GreaterOrEqual(t, em.countOf("capability_execution"), 1,
		"a capability_execution metric should be emitted for the WASM's SendRequest call")
	// Find the http-actions call and assert it succeeded with a duration.
	var found bool
	for _, ev := range em.events {
		if ev.Event == "capability_execution" && ev.Details["capability_id"] == httpserver.ClientID {
			found = true
			assert.Equal(t, true, ev.Details["success"])
			assert.Contains(t, ev.Details, "duration_seconds")
		}
	}
	assert.True(t, found, "expected a capability_execution event for %s", httpserver.ClientID)
}

func TestExecute_InvalidAppID(t *testing.T) {
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t))
	_, execErr := app.Execute([32]byte{}, "wrong-app-id", nil, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "invalid app ID")
}

func TestExecute_InvalidProto(t *testing.T) {
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t))
	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, []byte("not a proto"), nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "unable to unmarshal")
}

func TestExecute_MissingWorkflowID(t *testing.T) {
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t))
	execution := &confworkflowtypes.WorkflowExecution{
		BinaryUrl: "https://storage.example.com/binary.wasm",
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0}},
		},
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "workflow_id is required")
}

func TestExecute_MissingBinaryURL(t *testing.T) {
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t))
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId: "wf-123",
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0}},
		},
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "binary_url is required")
}

func TestExecute_MissingExecuteRequest(t *testing.T) {
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t))
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId: "wf-123",
		BinaryUrl:  "https://storage.example.com/binary.wasm",
		BinaryHash: make([]byte, 32),
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "execute_request is required")
}

func TestExecute_WasmExecutionFailure(t *testing.T) {
	// A fake binary that is not valid brotli/WASM: it fetches and hash-verifies
	// fine, then fails at wasm execution.
	fakeBinary := []byte("fake-wasm-binary-for-test")
	hash := sha256.Sum256(fakeBinary)

	app, _ := newStorageBackedApp(t, fakeBinary)
	execution := makeExecution(t, "wf-123", testLocator, hash[:])
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusInternalServerError, execErr.Code)
	assert.Contains(t, execErr.Error, "executing wasm")
}

func TestExecute_FetchFailure(t *testing.T) {
	// No credentials injected: the storage fetcher is never built, so the binary
	// fetch fails fast with a BadGateway.
	app := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), WithStorageService("127.0.0.1:1", false))

	execution := makeExecution(t, "wf-123", testLocator, make([]byte, 32))
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadGateway, execErr.Code)
	assert.Contains(t, execErr.Error, "fetching binary")
}

func TestExecute_EngineTestWasm_RemoteGetSecrets(t *testing.T) {
	// Build the engine-test WASM binary which calls getSecret("MOCK_SECRET"),
	// then callCapability("http-actions@1.0.0-alpha") and callCapability("basic-test-action@1.0.0").
	raw := buildTestWasm(t, "engine-test")
	var compressed bytes.Buffer
	bw := brotli.NewWriter(&compressed)
	_, err := bw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId: "wf-engine-test",
		BinaryUrl:  testLocator,
		BinaryHash: hash[:],
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Config: []byte(`{}`),
			Request: &sdkpb.ExecuteRequest_Trigger{
				Trigger: &sdkpb.Trigger{Id: 0, Payload: payload},
			},
		},
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	secretsCalled := false
	basicActionCalled := false
	stubDispatcher := &testRemoteDispatcher{
		secrets: map[string]string{"MOCK_SECRET": "s3cret-from-vault"},
		onGetSecrets: func() {
			secretsCalled = true
		},
		onCallCapability: func(_ context.Context, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
			basicActionCalled = true
			payload, err := anypb.New(&basicaction.Outputs{AdaptedThing: "done"})
			if err != nil {
				return nil, err
			}
			return &sdkpb.CapabilityResponse{
				Response: &sdkpb.CapabilityResponse_Payload{Payload: payload},
			}, nil
		},
	}

	app, _ := newStorageBackedApp(t, binary, WithRemoteDispatcher(stubDispatcher))

	output, execErr := app.Execute([32]byte{1}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.Nil(t, execErr, "expected no error, got: %+v", execErr)

	assert.True(t, secretsCalled, "expected GetSecrets to be called by WASM binary")
	assert.True(t, basicActionCalled, "expected basic-test-action capability to be called by WASM binary")

	// Unwrap and check the result.
	var cwResp confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(output, &cwResp))
	require.NotNil(t, cwResp.SdkExecutionResult)

	switch r := cwResp.SdkExecutionResult.Result.(type) {
	case *sdkpb.ExecutionResult_Value:
		val, err := values.FromProto(r.Value)
		require.NoError(t, err)
		unwrapped, err := val.Unwrap()
		require.NoError(t, err)
		resultMap, ok := unwrapped.(map[string]any)
		require.True(t, ok, "expected map result, got %T", unwrapped)
		assert.Equal(t, "s3cret-from-vault", resultMap["secret"])
	case *sdkpb.ExecutionResult_Error:
		t.Fatalf("WASM returned error: %s", r.Error)
	default:
		t.Fatalf("unexpected result type: %T", cwResp.SdkExecutionResult.Result)
	}
}

// An execution that outlives the injected timeout is a caller-facing 504, not
// an enclave failure, and it releases its execution slot instead of holding it
// for the WASM host's 10-minute default.
func TestExecute_ExecutionTimeout(t *testing.T) {
	raw := buildTestWasm(t, "spin")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	app, locator := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) {
		s.ExecutionTimeout = Duration(time.Second)
	})

	execution := makeExecution(t, "wf-spin", locator, hash[:])
	data, err := proto.Marshal(execution)
	require.NoError(t, err)

	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusGatewayTimeout, execErr.Code)
	assert.Contains(t, execErr.Error, context.DeadlineExceeded.Error())
	assert.Contains(t, execErr.Error, types.ErrWasmExecutionTimeout)
}

// startTimer records when workflow_execute_started is emitted.
type startTimer struct{ at time.Time }

func (s *startTimer) Emit(event string, _ map[string]any) {
	if event == "workflow_execute_started" {
		s.at = time.Now()
	}
}

// Every execution is held for the grace period before it starts; a negative
// setting turns the wait off entirely.
func TestExecute_GracePeriod(t *testing.T) {
	raw := buildTestWasm(t, "hello")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	run := func(t *testing.T, grace time.Duration) time.Duration {
		t.Helper()
		app, locator := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) {
			s.WorkflowGracePeriod = Duration(grace)
		})

		execution := makeExecution(t, "wf-grace", locator, hash[:])
		data, err := proto.Marshal(execution)
		require.NoError(t, err)

		// Measures up to workflow_execute_started so the WASM run, which is
		// slow under -race, does not count against the bound.
		started := &startTimer{}
		start := time.Now()
		_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, started)
		require.Nil(t, execErr, "expected no error, got: %+v", execErr)
		require.False(t, started.at.IsZero(), "workflow_execute_started was not emitted")
		return started.at.Sub(start)
	}

	t.Run("injected period is waited out", func(t *testing.T) {
		assert.GreaterOrEqual(t, run(t, 500*time.Millisecond), 500*time.Millisecond)
	})

	t.Run("negative disables the wait", func(t *testing.T) {
		assert.Less(t, run(t, -1), types.DefaultWorkflowGracePeriod)
	})
}

// The host injects both timeouts over vsock; the gateway one reaches the
// dispatcher factory and a zero leaves the factory's own fallback in charge.
func TestInjectSettings_Timeouts(t *testing.T) {
	newApp := func() (*confidentialWorkflowsApp, *time.Duration) {
		var got time.Duration
		a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t),
			WithRemoteDispatcherFactory(func(gw GatewayConfig) (RemoteDispatcher, error) {
				got = gw.RequestTimeout
				return &testRemoteDispatcher{}, nil
			}),
		).(*confidentialWorkflowsApp)
		return a, &got
	}

	// Storage is never dialed here (gRPC connects lazily), so a placeholder
	// endpoint is enough to satisfy the required settings.
	inject := func(t *testing.T, a *confidentialWorkflowsApp, mutate func(*WorkflowSettings)) {
		t.Helper()
		s := testSettings("127.0.0.1:1")
		mutate(&s)
		raw, err := json.Marshal(s)
		require.NoError(t, err)
		require.NoError(t, a.InjectSettings(raw))
	}

	t.Run("forwarded to the dispatcher factory", func(t *testing.T) {
		a, got := newApp()
		inject(t, a, func(s *WorkflowSettings) {
			s.RequestTimeout = Duration(80 * time.Second)
			s.GatewayRequestTimeout = Duration(75 * time.Second)
			s.ExecutionTimeout = Duration(80 * time.Second)
		})
		assert.Equal(t, 75*time.Second, *got)
		assert.Equal(t, int64(80*time.Second), a.executionTimeout.Load())
	})

	t.Run("omitted leaves the fallback to the factory", func(t *testing.T) {
		a, got := newApp()
		inject(t, a, func(*WorkflowSettings) {})
		assert.Zero(t, *got)
	})
}

// Only the first successful injection may replace the bootstrap compile gate.
func TestInjectSettings_MaxConcurrentCompilations(t *testing.T) {
	newApp := func(t *testing.T, capacity int64) *confidentialWorkflowsApp {
		t.Helper()
		app, err := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), Config{
			CompileCapacity: capacity,
			HTTPFetcher:     httpfetch.NewFetcher(httpfetch.DefaultPolicy()),
			StorageFetcherFactory: storageFetcherFactory(func() types.HTTPClient {
				return util.NewRestrictedHTTPClient()
			}),
			RemoteDispatcherFactory: func(GatewayConfig) (RemoteDispatcher, error) {
				return &testRemoteDispatcher{}, nil
			},
		})
		require.NoError(t, err)
		a := app.(*confidentialWorkflowsApp)
		t.Cleanup(func() {
			if a.storageFetcher != nil {
				require.NoError(t, a.storageFetcher.Close())
			}
		})
		return a
	}
	inject := func(t *testing.T, a *confidentialWorkflowsApp, mutate func(*WorkflowSettings)) error {
		t.Helper()
		s := testSettings("127.0.0.1:1")
		mutate(&s)
		raw, err := json.Marshal(s)
		require.NoError(t, err)
		return a.InjectSettings(raw)
	}
	// gateCapacity acquires until the gate refuses, then releases everything.
	gateCapacity := func(t *testing.T, gate *semaphore.Weighted) int64 {
		t.Helper()
		var n int64
		for gate.TryAcquire(1) {
			n++
		}
		for i := int64(0); i < n; i++ {
			gate.Release(1)
		}
		return n
	}

	t.Run("default gate", func(t *testing.T) {
		for _, capacity := range []int64{0, 8} {
			a := newApp(t, capacity)
			assert.Equal(t, int64(defaultMaxConcurrentCompilations), gateCapacity(t, a.compileSlots.Load()))
			require.NoError(t, inject(t, a, func(*WorkflowSettings) {}))
			assert.Equal(t, int64(defaultMaxConcurrentCompilations), gateCapacity(t, a.compileSlots.Load()))
		}
	})

	t.Run("injected value replaces the gate", func(t *testing.T) {
		for _, tc := range []struct{ capacity, requested, want int64 }{{0, 9, 9}, {2, 9, 2}, {8, 2, 2}} {
			a := newApp(t, tc.capacity)
			require.NoError(t, inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = tc.requested }))
			assert.Equal(t, tc.want, gateCapacity(t, a.compileSlots.Load()))
		}
	})

	t.Run("omitted keeps the existing gate", func(t *testing.T) {
		a := newApp(t, 0)
		require.NoError(t, inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = 2 }))
		gate := a.compileSlots.Load()
		require.NoError(t, inject(t, a, func(*WorkflowSettings) {}))
		require.Same(t, gate, a.compileSlots.Load())
		assert.Equal(t, int64(2), gateCapacity(t, a.compileSlots.Load()))
	})

	t.Run("negative rejected", func(t *testing.T) {
		a := newApp(t, 0)
		err := inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = -1 })
		require.ErrorContains(t, err, "maxConcurrentCompilations")
		assert.Equal(t, int64(defaultMaxConcurrentCompilations), gateCapacity(t, a.compileSlots.Load()))
	})

	t.Run("startup capacity bounds bootstrap default and requested concurrency", func(t *testing.T) {
		a := newApp(t, 2)
		require.Equal(t, int64(2), gateCapacity(t, a.compileSlots.Load()))
		require.NoError(t, inject(t, a, func(*WorkflowSettings) {}))
		gate := a.compileSlots.Load()
		require.True(t, gate.TryAcquire(2))
		defer gate.Release(2)
		for _, concurrency := range []int64{8, 2, 0} {
			require.NoError(t, inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = concurrency }))
			require.Same(t, gate, a.compileSlots.Load())
			require.False(t, a.compileSlots.Load().TryAcquire(1))
		}
		old := a.storageFetcher
		err := inject(t, a, func(s *WorkflowSettings) {
			s.MaxConcurrentCompilations = 1
			s.MaxCacheBytes = 1
			s.ExecutionTimeout = Duration(time.Second)
		})
		require.ErrorContains(t, err, "restart the enclave")
		require.Same(t, gate, a.compileSlots.Load())
		require.Same(t, old, a.storageFetcher)
		require.Equal(t, types.DefaultMaxBinaryCacheBytes, a.fetcher.maxCacheBytes)
		require.Zero(t, a.executionTimeout.Load())
	})

	t.Run("increasing configured concurrency requires restart too", func(t *testing.T) {
		a := newApp(t, 8)
		require.NoError(t, inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = 2 }))
		gate, old := a.compileSlots.Load(), a.storageFetcher
		a.storageFactory = func(string, bool, string, int64, time.Duration, logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
			t.Fatal("rejected concurrency change must not build a storage fetcher")
			return nil, nil, nil
		}
		for _, concurrency := range []int64{3, 9} {
			err := inject(t, a, func(s *WorkflowSettings) { s.MaxConcurrentCompilations = concurrency })
			require.ErrorContains(t, err, "restart the enclave")
			require.Same(t, gate, a.compileSlots.Load())
			require.Same(t, old, a.storageFetcher)
		}
	})

	t.Run("binary settings remain adjustable within budget", func(t *testing.T) {
		a := newApp(t, 2)
		for _, limit := range []int64{1 << 40, 1 << 20, 2 << 20, 0} {
			require.NoError(t, inject(t, a, func(s *WorkflowSettings) {
				s.MaxCacheBytes, s.MaxBinarySize = limit, limit
			}))
			if limit == 0 {
				require.Equal(t, 2<<20, a.fetcher.maxCacheBytes)
				require.EqualValues(t, types.DefaultMaxBinarySize, a.storageFetcher.(*StorageFetcher).maxBytes)
			} else {
				require.EqualValues(t, min(limit, types.DefaultMaxBinaryCacheBytes), a.fetcher.maxCacheBytes)
				require.Equal(t, min(limit, types.DefaultMaxBinarySize), a.storageFetcher.(*StorageFetcher).maxBytes)
			}
		}
	})

	t.Run("no startup budget preserves uncapped binary settings", func(t *testing.T) {
		a := newApp(t, 0)
		require.NoError(t, inject(t, a, func(s *WorkflowSettings) {
			s.MaxCacheBytes, s.MaxBinarySize = 1<<30, 1<<30
		}))
		require.Equal(t, 1<<30, a.fetcher.maxCacheBytes)
		require.EqualValues(t, 1<<30, a.storageFetcher.(*StorageFetcher).maxBytes)
	})

	for _, failure := range []string{"storage", "dispatcher"} {
		t.Run(failure+" failure does not freeze or apply settings", func(t *testing.T) {
			a := newApp(t, 2)
			gate := a.compileSlots.Load()
			storage, dispatcher := a.storageFactory, a.dispatcherFactory
			var candidate *StorageFetcher
			if failure == "storage" {
				a.storageFactory = func(string, bool, string, int64, time.Duration, logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
					return nil, nil, errors.New("storage failure")
				}
			} else {
				a.storageFactory = func(url string, tls bool, key string, maxBytes int64, timeout time.Duration, lggr logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
					f, pub, err := storage(url, tls, key, maxBytes, timeout, lggr)
					require.NoError(t, err)
					candidate = f.(*StorageFetcher)
					t.Cleanup(func() { _ = candidate.Close() })
					return f, pub, nil
				}
				a.dispatcherFactory = func(GatewayConfig) (RemoteDispatcher, error) {
					return nil, errors.New("dispatcher failure")
				}
			}
			configure := func(s *WorkflowSettings) {
				s.MaxConcurrentCompilations = 1
				s.MaxCacheBytes = 1
				s.ExecutionTimeout = Duration(time.Second)
				s.WorkflowGracePeriod = Duration(-time.Second)
			}
			require.ErrorContains(t, inject(t, a, configure), failure+" failure")
			require.Same(t, gate, a.compileSlots.Load())
			require.Zero(t, a.compileConcurrency)
			require.Nil(t, a.storageFetcher)
			require.Nil(t, a.dispatcher)
			require.Zero(t, a.executionTimeout.Load())
			require.Equal(t, types.DefaultMaxBinaryCacheBytes, a.fetcher.maxCacheBytes)
			require.Equal(t, int64(types.DefaultWorkflowGracePeriod), a.gracePeriod.Load())
			if candidate != nil {
				require.Equal(t, connectivity.Shutdown, candidate.conn.GetState(), "unused fetcher must be closed")
			}
			a.storageFactory, a.dispatcherFactory = storage, dispatcher
			require.NoError(t, inject(t, a, configure))
			require.Equal(t, int64(1), gateCapacity(t, a.compileSlots.Load()))
		})
	}

	t.Run("failed credential rotation preserves active settings", func(t *testing.T) {
		a := newApp(t, 2)
		require.NoError(t, inject(t, a, func(s *WorkflowSettings) {
			s.MaxConcurrentCompilations = 1
			s.MaxCacheBytes = 2 << 20
			s.ExecutionTimeout = Duration(3 * time.Second)
			s.WorkflowGracePeriod = Duration(-time.Second)
		}))
		gate, old, dispatcher := a.compileSlots.Load(), a.storageFetcher.(*StorageFetcher), a.dispatcher
		rotate := func(s *WorkflowSettings) {
			s.StorageKey = "invalid-key"
			s.MaxCacheBytes = 1 << 20
			s.ExecutionTimeout = Duration(time.Second)
			s.WorkflowGracePeriod = Duration(time.Second)
		}
		require.ErrorContains(t, inject(t, a, rotate), "building storage fetcher")
		require.Same(t, old, a.storageFetcher)
		require.NotEqual(t, connectivity.Shutdown, old.conn.GetState())
		require.Same(t, dispatcher, a.dispatcher)
		require.Same(t, gate, a.compileSlots.Load())
		require.Equal(t, 2<<20, a.fetcher.maxCacheBytes)
		require.Equal(t, int64(3*time.Second), a.executionTimeout.Load())
		require.Equal(t, int64(-time.Second), a.gracePeriod.Load())
		require.NoError(t, inject(t, a, func(s *WorkflowSettings) {
			rotate(s)
			s.StorageKey = fmt.Sprintf("%064x", 2)
		}))
		require.NotSame(t, old, a.storageFetcher)
		require.Equal(t, connectivity.Shutdown, old.conn.GetState())
		require.Same(t, gate, a.compileSlots.Load())
		require.Equal(t, int64(1), gateCapacity(t, a.compileSlots.Load()))
		require.Equal(t, 1<<20, a.fetcher.maxCacheBytes)
		require.Equal(t, int64(time.Second), a.executionTimeout.Load())
		require.Equal(t, int64(time.Second), a.gracePeriod.Load())
	})

	t.Run("concurrent injections install only one final gate", func(t *testing.T) {
		a := newApp(t, 2)
		entered, release := make(chan *semaphore.Weighted, 2), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		var wg sync.WaitGroup
		defer func() { unblock(); wg.Wait() }()
		a.storageFactory = func(string, bool, string, int64, time.Duration, logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
			entered <- a.compileSlots.Load()
			<-release
			return &stubRawFetcher{}, nil, nil
		}
		settings := testSettings("127.0.0.1:1")
		settings.MaxConcurrentCompilations = 1
		raw, err := json.Marshal(settings)
		require.NoError(t, err)
		results := make(chan error, 2)
		wg.Go(func() { results <- a.InjectSettings(raw) })
		bootstrap := <-entered
		a.mu.Lock()
		sf := a.storageFetcher
		a.mu.Unlock()
		_, err = a.fetcher.Fetch(t.Context(), "unused", testBinaryHash(), sf)
		require.ErrorContains(t, err, "credentials not yet provisioned")
		wg.Go(func() { results <- a.InjectSettings(raw) })
		select {
		case <-entered:
			t.Fatal("settings factories ran concurrently")
		case <-time.After(100 * time.Millisecond):
		}
		unblock()
		for range 2 {
			require.NoError(t, <-results)
		}
		require.NotSame(t, bootstrap, a.compileSlots.Load())
		require.Same(t, <-entered, a.compileSlots.Load())
		require.Equal(t, int64(1), gateCapacity(t, a.compileSlots.Load()))
	})
}

// A payload missing required settings is rejected whole, and nothing is applied:
// the enclave stays unconfigured instead of running half-configured until an
// execution trips over the gap.
func TestInjectSettings_RequiredFields(t *testing.T) {
	a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t),
		WithRemoteDispatcherFactory(func(GatewayConfig) (RemoteDispatcher, error) { return &testRemoteDispatcher{}, nil }),
	).(*confidentialWorkflowsApp)

	err := a.InjectSettings([]byte(`{"requestTimeout":"80s"}`))
	require.Error(t, err)
	for _, field := range []string{"storageKey", "storageServiceUrl", "gatewayUrl"} {
		assert.Contains(t, err.Error(), field)
	}

	a.mu.Lock()
	fetcher, dispatcher := a.storageFetcher, a.dispatcher
	a.mu.Unlock()
	assert.Nil(t, fetcher)
	assert.Nil(t, dispatcher)
}

// Durations arrive as the readable strings deployment config hand-writes; raw
// nanoseconds still parse, and an unparsable duration fails the injection.
func TestInjectSettings_DurationForms(t *testing.T) {
	newApp := func() *confidentialWorkflowsApp {
		return NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t)).(*confidentialWorkflowsApp)
	}
	payload := func(execTimeout, gracePeriod string) []byte {
		return []byte(fmt.Sprintf(
			`{"storageKey":%q,"storageServiceUrl":"127.0.0.1:1","gatewayUrl":%q,"executionTimeout":%s,"workflowGracePeriod":%s}`,
			testStorageKeyHex, testGatewayURL, execTimeout, gracePeriod))
	}

	t.Run("duration string", func(t *testing.T) {
		a := newApp()
		require.NoError(t, a.InjectSettings(payload(`"80s"`, `"-1ns"`)))
		assert.Equal(t, int64(80*time.Second), a.executionTimeout.Load())
		assert.Equal(t, int64(-1), a.gracePeriod.Load())
	})

	t.Run("nanoseconds", func(t *testing.T) {
		a := newApp()
		require.NoError(t, a.InjectSettings(payload(`80000000000`, `-1`)))
		assert.Equal(t, int64(80*time.Second), a.executionTimeout.Load())
		assert.Equal(t, int64(-1), a.gracePeriod.Load())
	})

	t.Run("unparsable", func(t *testing.T) {
		err := newApp().InjectSettings(payload(`"80 seconds"`, `0`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "80 seconds")
	})
}

func TestInsecureArtifactHTTPComesOnlyFromTheEntrypoint(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "d2FzbQ==") // base64("wasm")
	}))
	t.Cleanup(httpServer.Close)

	raw, err := json.Marshal(WorkflowSettings{
		StorageKey:        testStorageKeyHex,
		StorageServiceURL: "127.0.0.1:1",
		GatewayURL:        testGatewayURL,
	})
	require.NoError(t, err)

	download := func(opts ...Option) ([]byte, error) {
		a := NewTestConfidentialWorkflowsApp(
			sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), opts...,
		).(*confidentialWorkflowsApp)
		require.NoError(t, a.InjectSettings(raw))
		t.Cleanup(func() { require.NoError(t, a.storageFetcher.Close()) })
		fetcher, ok := a.storageFetcher.(*StorageFetcher)
		require.True(t, ok)
		return fetcher.download(context.Background(), httpServer.URL)
	}

	_, err = download()
	require.Error(t, err, "the default test client must require HTTPS artifacts")
	got, err := download(withInsecureArtifactHTTP())
	require.NoError(t, err)
	require.Equal(t, []byte("wasm"), got)
}

func withInsecureArtifactHTTP() Option {
	return func(a *confidentialWorkflowsApp) {
		a.storageFactory = storageFetcherFactory(func() types.HTTPClient {
			return util.NewUnrestrictedClient()
		})
	}
}

// testRemoteDispatcher is a stub that returns pre-configured secrets and
// optionally handles capability calls via onCallCapability.
type testRemoteDispatcher struct {
	secrets          map[string]string
	onGetSecrets     func()
	onCallCapability func(context.Context, *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error)
}

func (d *testRemoteDispatcher) SetConfig(_ types.EnclaveConfig) {}

func (d *testRemoteDispatcher) CallCapability(ctx context.Context, _ string, _ string, _ string, _ string, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	if d.onCallCapability != nil {
		return d.onCallCapability(ctx, req)
	}
	// Default: echo payload back.
	return &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Payload{Payload: req.Payload},
	}, nil
}

func (d *testRemoteDispatcher) GetSecrets(_ context.Context, _ string, _ [32]byte, req *sdkpb.GetSecretsRequest, _ string, _ string, _ string, _ []types.SignedComputeRequest) ([]*sdkpb.SecretResponse, error) {
	if d.onGetSecrets != nil {
		d.onGetSecrets()
	}
	var responses []*sdkpb.SecretResponse
	for _, sr := range req.GetRequests() {
		val, ok := d.secrets[sr.GetId()]
		if !ok {
			responses = append(responses, &sdkpb.SecretResponse{
				Response: &sdkpb.SecretResponse_Error{
					Error: &sdkpb.SecretError{
						Id:    sr.GetId(),
						Error: fmt.Sprintf("secret %q not found", sr.GetId()),
					},
				},
			})
			continue
		}
		responses = append(responses, &sdkpb.SecretResponse{
			Response: &sdkpb.SecretResponse_Secret{
				Secret: &sdkpb.Secret{
					Id:    sr.GetId(),
					Value: val,
				},
			},
		})
	}
	return responses, nil
}
