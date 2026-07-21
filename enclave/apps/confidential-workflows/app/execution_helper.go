package app

import (
	"context"
	"fmt"
	"time"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	httpserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http/server"
	consensusserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/consensus/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	valuespb "github.com/smartcontractkit/chainlink-protos/cre/go/values/pb"
	wfpb "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// enclaveExecutionHelper implements host.ExecutionHelper, dispatching capability
// calls and secret requests. Constructed per-Execute call.
//
// Capability calls are handled in three tiers:
//  1. Self-call guard: confidential-workflows itself is rejected as recursive.
//  2. Local interception: http-actions/SendRequest and consensus/Simple are
//     executed inside the enclave rather than forwarded. http-actions runs via
//     httpFetcher with a fixed safety policy. consensus/Simple returns the
//     single observation verbatim: a confidential workflow has one observer
//     per execution (this enclave), so TEE attestation substitutes for F+1
//     byzantine aggregation. The SDK's http.SendRequest(..., aggregation)
//     emits both capability calls; intercepting both makes the aggregation
//     sugar work end-to-end without round-tripping to the relay DON.
//  3. Everything else falls through to remoteDispatcher, or errors if nil.
type enclaveExecutionHelper struct {
	requestID        [32]byte
	workflowID       string
	owner            string
	executionID      string
	orgID            string
	signedRequests   []types.SignedComputeRequest
	logger           logger.Logger
	emitter          types.Emitter
	remoteDispatcher RemoteDispatcher
	httpFetcher      *httpfetch.Fetcher
}

var _ host.ExecutionHelper = (*enclaveExecutionHelper)(nil)

// emit forwards an observability event to the per-request emitter, which buffers
// it into the (non-attested) response for the host to re-emit as OTel metrics
// tagged with enclave metadata. Nil-safe so the helper works with an emitter-less
// test setup.
func (h *enclaveExecutionHelper) emit(event string, details map[string]any) {
	if h.emitter == nil {
		return
	}
	h.emitter.Emit(event, details)
}

// CallCapability wraps every capability dispatch with observability events, at the
// wrapper (not in remoteDispatcher) so all tiers are covered: http-actions and
// consensus.Simple are intercepted locally and never reach the dispatcher.
//
// Three events per call, all riding the ordered MetricEvents list (N calls -> N of
// each), broken down by capability_id:
//   - capability_started / capability_finished: lifecycle events mirroring the
//     DON-mode EmitCapabilityStartedEvent / EmitCapabilityFinishedEvent. Because
//     the enclave call is one round-trip, both arrive batched at response time;
//     started carries no timing.
//   - capability_execution: the metric vehicle (count + duration histogram),
//     mirroring platform_engine_capabilities_count / _capability_execution_time_seconds.
func (h *enclaveExecutionHelper) CallCapability(ctx context.Context, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	h.emit("capability_started", map[string]any{
		"capability_id": req.GetId(),
		"method":        req.GetMethod(),
		"step_ref":      req.GetCallbackId(),
	})

	start := time.Now()
	resp, err := h.callCapability(ctx, req)
	success := err == nil && resp.GetError() == ""

	var errType, errMsg string
	switch {
	case err != nil:
		errType = "dispatch"
		errMsg = err.Error()
	case resp.GetError() != "":
		errType = "capability"
		errMsg = resp.GetError()
	}

	execution := map[string]any{
		"capability_id":    req.GetId(),
		"success":          success,
		"duration_seconds": time.Since(start).Seconds(),
	}
	finished := map[string]any{
		"capability_id": req.GetId(),
		"method":        req.GetMethod(),
		"step_ref":      req.GetCallbackId(),
		"success":       success,
	}
	if errType != "" {
		execution["error_type"] = errType
		finished["error_type"] = errType
		finished["error"] = errMsg
	}
	h.emit("capability_execution", execution)
	h.emit("capability_finished", finished)
	return resp, err
}

func (h *enclaveExecutionHelper) callCapability(ctx context.Context, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	// Method names are string literals rather than constants from chainlink-common:
	// the generated servers in chainlink-common dispatch via `case "SendRequest":`
	// / `case "Simple":` themselves and expose no exported method-name constants.
	// A rename on the upstream proto would be a wire-breaking change, so would
	// bump the capability ID; the ID-level switch below would miss the new ID
	// and fall through to remote dispatch cleanly.
	switch req.GetId() {
	case types.AppIDConfidentialWorkflows:
		return errResponse("confidential-workflows cannot be called from within a workflow"), nil
	case httpserver.ClientID:
		if req.GetMethod() == "SendRequest" {
			return h.handleHTTPAction(ctx, req)
		}
	case consensusserver.ConsensusID:
		if req.GetMethod() == "Simple" {
			return h.handleConsensusSimple(req)
		}
	}
	if h.remoteDispatcher != nil {
		return h.remoteDispatcher.CallCapability(ctx, h.workflowID, h.owner, h.executionID, h.orgID, req)
	}
	return errResponse(fmt.Sprintf("failed to call capability %q, remote capability calls are not supported", req.GetId())), nil
}

func (h *enclaveExecutionHelper) handleHTTPAction(ctx context.Context, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	if h.httpFetcher == nil {
		return errResponse("http-actions: no HTTP fetcher configured"), nil
	}
	input := &httpcap.Request{}
	if err := req.GetPayload().UnmarshalTo(input); err != nil {
		return errResponse(fmt.Sprintf("http-actions: unmarshalling request: %v", err)), nil
	}
	resp, err := h.httpFetcher.Fetch(ctx, input)
	if err != nil {
		return errResponse(fmt.Sprintf("http-actions: %v", err)), nil
	}
	payload, err := anypb.New(resp)
	if err != nil {
		return errResponse(fmt.Sprintf("http-actions: marshalling response: %v", err)), nil
	}
	return &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Payload{Payload: payload},
	}, nil
}

func (h *enclaveExecutionHelper) handleConsensusSimple(req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	inputs := &sdkpb.SimpleConsensusInputs{}
	if err := req.GetPayload().UnmarshalTo(inputs); err != nil {
		return errResponse(fmt.Sprintf("consensus.Simple: unmarshalling inputs: %v", err)), nil
	}
	switch obs := inputs.GetObservation().(type) {
	case *sdkpb.SimpleConsensusInputs_Value:
		return wrapValueResponse(obs.Value)
	case *sdkpb.SimpleConsensusInputs_Error:
		// Fall back to Default if the observation failed and a default was provided.
		if def := inputs.GetDefault(); def != nil {
			return wrapValueResponse(def)
		}
		return errResponse(fmt.Sprintf("consensus.Simple: observation error: %s", obs.Error)), nil
	default:
		return errResponse("consensus.Simple: missing observation"), nil
	}
}

func wrapValueResponse(v *valuespb.Value) (*sdkpb.CapabilityResponse, error) {
	payload := &anypb.Any{}
	if err := anypb.MarshalFrom(payload, v, proto.MarshalOptions{Deterministic: true}); err != nil {
		return errResponse(fmt.Sprintf("marshalling value: %v", err)), nil
	}
	return &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Payload{Payload: payload},
	}, nil
}

func errResponse(msg string) *sdkpb.CapabilityResponse {
	return &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Error{Error: msg},
	}
}

// GetSecrets wraps the fetch with a per-call observability event mirroring the
// DON-mode platform_engine_get_secrets_duration_ms metric.
func (h *enclaveExecutionHelper) GetSecrets(ctx context.Context, req *sdkpb.GetSecretsRequest) (resp []*sdkpb.SecretResponse, err error) {
	h.logger.Infof("[ExecutionHelper.GetSecrets] called, remoteDispatcher=%v, numRequests=%d", h.remoteDispatcher != nil, len(req.GetRequests()))
	start := time.Now()
	defer func() {
		h.emit("get_secrets", map[string]any{
			"success":          err == nil,
			"num_requests":     len(req.GetRequests()),
			"duration_seconds": time.Since(start).Seconds(),
		})
	}()
	if h.remoteDispatcher == nil {
		return nil, fmt.Errorf("remote dispatcher is required for secret fetching")
	}
	return h.remoteDispatcher.GetSecrets(ctx, h.workflowID, h.requestID, req, h.owner, h.executionID, h.orgID, h.signedRequests)
}

func (h *enclaveExecutionHelper) GetWorkflowExecutionID() string { return h.executionID }

// Stubbed: not yet wired to real enclave services. Returns reasonable defaults.
func (h *enclaveExecutionHelper) GetNodeTime() time.Time         { return time.Now() }
func (h *enclaveExecutionHelper) GetDONTime() (time.Time, error) { return time.Now(), nil }

// EmitUserLog forwards a workflow author's log line so it surfaces on the workflow
// DON for debugging. The content is author-controlled and rides out in the
// non-attested response, so authors must not log secrets: there is no redaction
// here (leak control is author discipline, per PRIV-443). Per-line length and
// per-execution count are already bounded by the WASM host (MaxLogLenBytes /
// MaxLogCountNodeMode) before this is called, so the response stays bounded.
func (h *enclaveExecutionHelper) EmitUserLog(msg string) error {
	h.emit("user_log", map[string]any{
		"message":      msg,
		"workflow_id":  h.workflowID,
		"execution_id": h.executionID,
	})
	return nil
}

// EmitUserMetric forwards a workflow author's metric. The host re-emits it as a
// user_metric counter with enclave tagging; name/value/type/labels ride as attributes.
// The upstream WASM host rate-limits these calls.
func (h *enclaveExecutionHelper) EmitUserMetric(_ context.Context, m *wfpb.WorkflowUserMetric) error {
	details := map[string]any{
		"name":         m.GetName(),
		"value":        m.GetValue(),
		"metric_type":  m.GetType().String(),
		"workflow_id":  h.workflowID,
		"execution_id": h.executionID,
	}
	for k, v := range m.GetLabels() {
		details["label."+k] = v
	}
	h.emit("user_metric", details)
	return nil
}
