package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/andybalholm/brotli"
	"github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basicaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil)
	_, execErr := app.Execute([32]byte{}, "wrong-app-id", nil, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "invalid app ID")
}

func TestExecute_InvalidProto(t *testing.T) {
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil)
	_, execErr := app.Execute([32]byte{}, types.AppIDConfidentialWorkflows, []byte("not a proto"), nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execErr)
	assert.Equal(t, http.StatusBadRequest, execErr.Code)
	assert.Contains(t, execErr.Error, "unable to unmarshal")
}

func TestExecute_MissingWorkflowID(t *testing.T) {
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil)
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
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil)
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
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil)
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
	app := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil, WithStorageService("127.0.0.1:1", false))

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
