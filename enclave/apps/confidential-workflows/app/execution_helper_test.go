package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	httpserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http/server"
	consensusserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/consensus/server"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	valuespb "github.com/smartcontractkit/chainlink-protos/cre/go/values/pb"
	wfpb "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// recordingEmitter is a test types.Emitter that keeps every event in order.
type recordingEmitter struct{ events []types.MetricEvent }

func (r *recordingEmitter) Emit(event string, details map[string]any) {
	r.events = append(r.events, types.MetricEvent{Event: event, Details: details})
}

func (r *recordingEmitter) countOf(event string) int {
	n := 0
	for _, e := range r.events {
		if e.Event == event {
			n++
		}
	}
	return n
}

// lastDetails returns the details of the last event with the given name.
func (r *recordingEmitter) lastDetails(event string) map[string]any {
	var d map[string]any
	for _, e := range r.events {
		if e.Event == event {
			d = e.Details
		}
	}
	return d
}

func TestCallCapability_EmitsPerCallMetric(t *testing.T) {
	em := &recordingEmitter{}
	helper := &enclaveExecutionHelper{logger: logger.Test(t), emitter: em}

	// Two calls to an unknown (remote) capability: each should emit its own event,
	// classified as a capability-level failure.
	for i := 0; i < 2; i++ {
		_, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
			Id:     "write_ethereum@1.0.0",
			Method: "Transmit",
		})
		require.NoError(t, err)
	}

	require.Equal(t, 2, em.countOf("capability_execution"), "each call must emit its own event")
	last := em.lastDetails("capability_execution")
	assert.Equal(t, "write_ethereum@1.0.0", last["capability_id"])
	assert.Equal(t, false, last["success"])
	assert.Equal(t, "capability", last["error_type"])
	assert.Contains(t, last, "duration_seconds")
}

func TestCallCapability_EmitsStartedAndFinished(t *testing.T) {
	em := &recordingEmitter{}
	helper := &enclaveExecutionHelper{logger: logger.Test(t), emitter: em}

	_, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:     "write_ethereum@1.0.0",
		Method: "Transmit",
	})
	require.NoError(t, err)

	require.Equal(t, 1, em.countOf("capability_started"))
	require.Equal(t, 1, em.countOf("capability_finished"))

	// started fires before the call and carries the method.
	require.Equal(t, "capability_started", em.events[0].Event, "started must be emitted first")
	assert.Equal(t, "Transmit", em.events[0].Details["method"])
	assert.Equal(t, "write_ethereum@1.0.0", em.events[0].Details["capability_id"])

	// finished carries success/error_type for the failed remote call.
	var fin map[string]any
	for _, e := range em.events {
		if e.Event == "capability_finished" {
			fin = e.Details
		}
	}
	require.NotNil(t, fin)
	assert.Equal(t, false, fin["success"])
	assert.Equal(t, "capability", fin["error_type"])
	assert.Equal(t, "Transmit", fin["method"])
}

func TestCallCapability_EmitsSuccessMetric(t *testing.T) {
	em := &recordingEmitter{}
	helper := &enclaveExecutionHelper{logger: logger.Test(t), emitter: em}

	wrapped, err := values.Wrap(int64(1))
	require.NoError(t, err)
	inputs := &sdkpb.SimpleConsensusInputs{
		Observation: &sdkpb.SimpleConsensusInputs_Value{Value: values.Proto(wrapped)},
	}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, inputs, proto.MarshalOptions{Deterministic: true}))

	_, err = helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      consensusserver.ConsensusID,
		Method:  "Simple",
		Payload: payload,
	})
	require.NoError(t, err)

	require.Equal(t, 1, em.countOf("capability_execution"))
	ev := em.lastDetails("capability_execution")
	assert.Equal(t, true, ev["success"])
	assert.NotContains(t, ev, "error_type")
}

func TestGetSecrets_EmitsMetricOnFailure(t *testing.T) {
	em := &recordingEmitter{}
	h := &enclaveExecutionHelper{remoteDispatcher: nil, logger: logger.Test(t), emitter: em}

	_, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{
		Requests: []*sdkpb.SecretRequest{{Id: "K", Namespace: "default"}},
	})
	require.Error(t, err)

	require.Equal(t, 1, em.countOf("get_secrets"))
	ev := em.events[0]
	assert.Equal(t, false, ev.Details["success"])
	assert.Equal(t, 1, ev.Details["num_requests"])
}

func TestEmitUserLog_ForwardsToEmitter(t *testing.T) {
	em := &recordingEmitter{}
	h := &enclaveExecutionHelper{workflowID: "wf", executionID: "ex", emitter: em}

	require.NoError(t, h.EmitUserLog("hello"))
	require.NoError(t, h.EmitUserLog("world"))

	require.Equal(t, 2, em.countOf("user_log"), "each log line is its own event")
	assert.Equal(t, "hello", em.events[0].Details["message"])
	assert.Equal(t, "wf", em.events[0].Details["workflow_id"])
}

func TestEmitUserMetric_ForwardsNameValueTypeLabels(t *testing.T) {
	em := &recordingEmitter{}
	h := &enclaveExecutionHelper{workflowID: "wf", executionID: "ex", emitter: em}

	err := h.EmitUserMetric(context.Background(), &wfpb.WorkflowUserMetric{
		Name:   "orders_processed",
		Value:  7,
		Type:   wfpb.UserMetricType_USER_METRIC_TYPE_COUNTER,
		Labels: map[string]string{"region": "us-east"},
	})
	require.NoError(t, err)

	require.Equal(t, 1, em.countOf("user_metric"))
	d := em.events[0].Details
	assert.Equal(t, "orders_processed", d["name"])
	assert.Equal(t, float64(7), d["value"])
	assert.Equal(t, "USER_METRIC_TYPE_COUNTER", d["metric_type"])
	assert.Equal(t, "us-east", d["label.region"])
}

func TestEmitUser_NilEmitterSafe(t *testing.T) {
	h := &enclaveExecutionHelper{} // emitter nil
	require.NoError(t, h.EmitUserLog("x"))
	require.NoError(t, h.EmitUserMetric(context.Background(), &wfpb.WorkflowUserMetric{Name: "n"}))
}

func TestCallCapability_NilEmitterSafe(t *testing.T) {
	helper := &enclaveExecutionHelper{logger: logger.Test(t)} // emitter nil
	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id: "write_ethereum@1.0.0", Method: "Transmit",
	})
	require.NoError(t, err)
	assert.Contains(t, resp.GetError(), "remote capability calls are not supported")
}

func TestCallCapability_ConfidentialWorkflowsBlocked(t *testing.T) {
	helper := &enclaveExecutionHelper{
		logger: logger.Test(t),
	}

	capReq := &sdkpb.CapabilityRequest{
		Id:     types.AppIDConfidentialWorkflows,
		Method: "Execute",
	}

	resp, err := helper.CallCapability(context.Background(), capReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	errMsg := resp.GetError()
	assert.Contains(t, errMsg, "cannot be called from within a workflow")
}

func TestCallCapability_UnknownCapability(t *testing.T) {
	helper := &enclaveExecutionHelper{
		logger: logger.Test(t),
	}

	capReq := &sdkpb.CapabilityRequest{
		Id:     "write_ethereum@1.0.0",
		Method: "Transmit",
	}

	resp, err := helper.CallCapability(context.Background(), capReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	errMsg := resp.GetError()
	assert.Contains(t, errMsg, "write_ethereum@1.0.0")
	assert.Contains(t, errMsg, "remote capability calls are not supported")
}

func TestGetSecrets_RequiresRemoteDispatcher(t *testing.T) {
	h := &enclaveExecutionHelper{
		remoteDispatcher: nil,
		logger:           logger.Test(t),
	}

	_, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{
		Requests: []*sdkpb.SecretRequest{
			{Id: "ANY_KEY", Namespace: "default"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote dispatcher is required")
}

func TestGetWorkflowExecutionID_ReturnsExecutionID(t *testing.T) {
	h := &enclaveExecutionHelper{
		workflowID:  "workflow-id",
		executionID: "execution-id",
	}

	assert.Equal(t, "execution-id", h.GetWorkflowExecutionID())
}

func permissiveFetcher() *httpfetch.Fetcher {
	// Inject an unrestricted client so the fetcher can reach loopback test
	// servers the restricted client would block.
	return httpfetch.NewFetcherWithClient(httpfetch.Policy{
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		DefaultTimeout:       time.Second,
		MaxResponseBodyBytes: 1 << 20,
	}, util.NewUnrestrictedClient())
}

func TestCallCapability_InterceptsHTTPAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "hello", string(body))
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("thanks"))
	}))
	t.Cleanup(srv.Close)

	helper := &enclaveExecutionHelper{
		logger:      logger.Test(t),
		httpFetcher: permissiveFetcher(),
	}

	input := &httpcap.Request{
		Url:    srv.URL,
		Method: "POST",
		Body:   []byte("hello"),
	}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, input, proto.MarshalOptions{Deterministic: true}))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      httpserver.ClientID,
		Method:  "SendRequest",
		Payload: payload,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetPayload())
	assert.Empty(t, resp.GetError())

	out := &httpcap.Response{}
	require.NoError(t, resp.GetPayload().UnmarshalTo(out))
	assert.Equal(t, uint32(http.StatusAccepted), out.StatusCode)
	assert.Equal(t, "thanks", string(out.Body))
}

func TestCallCapability_InterceptsHTTPAction_SSRFBlockReturns400(t *testing.T) {
	helper := &enclaveExecutionHelper{
		logger:      logger.Test(t),
		httpFetcher: httpfetch.NewFetcher(httpfetch.DefaultPolicy()), // https-only, blocks loopback
	}

	input := &httpcap.Request{Url: "http://127.0.0.1:80/", Method: "GET"}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, input, proto.MarshalOptions{Deterministic: true}))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      httpserver.ClientID,
		Method:  "SendRequest",
		Payload: payload,
	})
	// An SSRF-policy block is caller-facing: it surfaces as a 400 response in
	// the payload, not a capability error.
	require.NoError(t, err)
	require.Empty(t, resp.GetError())
	require.NotNil(t, resp.GetPayload())

	out := &httpcap.Response{}
	require.NoError(t, resp.GetPayload().UnmarshalTo(out))
	assert.Equal(t, uint32(http.StatusBadRequest), out.StatusCode)
	assert.Equal(t, "upstream request blocked by enclave network policy", string(out.Body))
}

func TestCallCapability_InterceptsConsensusSimple_PassesValueThrough(t *testing.T) {
	helper := &enclaveExecutionHelper{logger: logger.Test(t)}

	wrapped, err := values.Wrap(int64(42))
	require.NoError(t, err)

	inputs := &sdkpb.SimpleConsensusInputs{
		Observation: &sdkpb.SimpleConsensusInputs_Value{Value: values.Proto(wrapped)},
	}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, inputs, proto.MarshalOptions{Deterministic: true}))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      consensusserver.ConsensusID,
		Method:  "Simple",
		Payload: payload,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetPayload())
	assert.Empty(t, resp.GetError())

	got := &valuespb.Value{}
	require.NoError(t, resp.GetPayload().UnmarshalTo(got))
	v, err := values.FromProto(got)
	require.NoError(t, err)
	var out int64
	require.NoError(t, v.UnwrapTo(&out))
	assert.Equal(t, int64(42), out)
}

func TestCallCapability_InterceptsConsensusSimple_ObservationErrorFallsBackToDefault(t *testing.T) {
	helper := &enclaveExecutionHelper{logger: logger.Test(t)}

	def, err := values.Wrap("fallback")
	require.NoError(t, err)

	inputs := &sdkpb.SimpleConsensusInputs{
		Observation: &sdkpb.SimpleConsensusInputs_Error{Error: "boom"},
		Default:     values.Proto(def),
	}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, inputs, proto.MarshalOptions{Deterministic: true}))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      consensusserver.ConsensusID,
		Method:  "Simple",
		Payload: payload,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetPayload())

	got := &valuespb.Value{}
	require.NoError(t, resp.GetPayload().UnmarshalTo(got))
	v, err := values.FromProto(got)
	require.NoError(t, err)
	var out string
	require.NoError(t, v.UnwrapTo(&out))
	assert.Equal(t, "fallback", out)
}

func TestCallCapability_InterceptsConsensusSimple_ObservationErrorNoDefaultErrors(t *testing.T) {
	helper := &enclaveExecutionHelper{logger: logger.Test(t)}

	inputs := &sdkpb.SimpleConsensusInputs{
		Observation: &sdkpb.SimpleConsensusInputs_Error{Error: "boom"},
	}
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, inputs, proto.MarshalOptions{Deterministic: true}))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      consensusserver.ConsensusID,
		Method:  "Simple",
		Payload: payload,
	})
	require.NoError(t, err)
	assert.Contains(t, resp.GetError(), "observation error: boom")
}

func TestCallCapability_ConsensusReportStillRoutesRemote(t *testing.T) {
	// consensus/Report is NOT intercepted; it should fall through to the
	// remote-dispatcher path (and here error with the "not configured" message).
	helper := &enclaveExecutionHelper{logger: logger.Test(t)}

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:     consensusserver.ConsensusID,
		Method: "Report",
	})
	require.NoError(t, err)
	assert.Contains(t, resp.GetError(), "remote capability calls are not supported")
}
