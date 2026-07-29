package main

import (
	"encoding/hex"
	"maps"
	"slices"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	confhttptypes "github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"google.golang.org/protobuf/proto"
)

type executionMetadata struct {
	appID       string
	workflowID  string
	requestKind string
}

// inspectPublicData decodes public data once so app-specific logging and
// execution metrics derive their observations from the same typed message.
func inspectPublicData(reqLog cllogger.SugaredLogger, appID string, publicData []byte) executionMetadata {
	switch appID {
	case types.AppIDConfidentialHTTP:
		req, err := decodeHTTPPublicData(publicData)
		if err != nil {
			logPublicDataDecodeError(reqLog, appID, len(publicData), err)
			return executionMetadata{appID: appID}
		}

		metadata := httpExecutionMetadata()
		logHTTPPublicData(reqLog, req, len(publicData))
		return metadata

	case types.AppIDConfidentialWorkflows:
		execution, err := decodeWorkflowPublicData(publicData)
		if err != nil {
			logPublicDataDecodeError(reqLog, appID, len(publicData), err)
			return executionMetadata{appID: appID}
		}

		metadata := workflowExecutionMetadata(execution)
		logWorkflowPublicData(reqLog, execution, len(publicData))
		return metadata

	default:
		reqLog.Debugw("publicData decoder unavailable",
			"event", "PUBLIC_DATA_UNSUPPORTED",
			"appID", appID,
			"publicDataLen", len(publicData))
		return executionMetadata{appID: appID}
	}
}

// inspectResponseOutput decodes an execute-response output so response logging
// derives its observations from the same typed message the enclave produced.
func inspectResponseOutput(reqLog cllogger.SugaredLogger, appID string, output []byte) {
	switch appID {
	case types.AppIDConfidentialHTTP:
		resp, err := decodeHTTPResponseOutput(output)
		if err != nil {
			logResponseOutputDecodeError(reqLog, appID, len(output), err)
			return
		}

		logHTTPResponseOutput(reqLog, resp, len(output))

	case types.AppIDConfidentialWorkflows:
		resp, err := decodeWorkflowResponseOutput(output)
		if err != nil {
			logResponseOutputDecodeError(reqLog, appID, len(output), err)
			return
		}

		logWorkflowResponseOutput(reqLog, resp, len(output))

	default:
		reqLog.Debugw("response output decoder unavailable",
			"event", "RESPONSE_DATA_UNSUPPORTED",
			"appID", appID,
			"outputLen", len(output))
	}
}

func decodeHTTPPublicData(publicData []byte) (*confhttptypes.Request, error) {
	var req confhttptypes.Request
	if err := proto.Unmarshal(publicData, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func decodeHTTPResponseOutput(output []byte) (*confhttptypes.Response, error) {
	var resp confhttptypes.Response
	if err := proto.Unmarshal(output, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func decodeWorkflowResponseOutput(output []byte) (*confworkflowtypes.ConfidentialWorkflowResponse, error) {
	var resp confworkflowtypes.ConfidentialWorkflowResponse
	if err := proto.Unmarshal(output, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func decodeWorkflowPublicData(publicData []byte) (*confworkflowtypes.WorkflowExecution, error) {
	var execution confworkflowtypes.WorkflowExecution
	if err := proto.Unmarshal(publicData, &execution); err != nil {
		return nil, err
	}
	return &execution, nil
}

func httpExecutionMetadata() executionMetadata {
	return executionMetadata{appID: types.AppIDConfidentialHTTP}
}

func workflowExecutionMetadata(execution *confworkflowtypes.WorkflowExecution) executionMetadata {
	return executionMetadata{
		appID:       types.AppIDConfidentialWorkflows,
		workflowID:  execution.GetWorkflowId(),
		requestKind: workflowRequestKind(execution),
	}
}

func workflowRequestKind(execution *confworkflowtypes.WorkflowExecution) string {
	if execReq := execution.GetSdkExecuteRequest(); execReq != nil {
		switch execReq.GetRequest().(type) {
		case *sdkpb.ExecuteRequest_Subscribe:
			return "subscribe"
		case *sdkpb.ExecuteRequest_Trigger:
			return "trigger"
		case *sdkpb.ExecuteRequest_PreHook:
			return "pre_hook"
		}
	}
	return "unset"
}

func workflowResultKind(result *sdkpb.ExecutionResult) string {
	switch result.GetResult().(type) {
	case *sdkpb.ExecutionResult_Value:
		return "value"
	case *sdkpb.ExecutionResult_Error:
		return "error"
	case *sdkpb.ExecutionResult_TriggerSubscriptions:
		return "trigger_subscriptions"
	case *sdkpb.ExecutionResult_Restrictions:
		return "restrictions"
	}
	return "unset"
}

func logHTTPPublicData(reqLog cllogger.SugaredLogger, req *confhttptypes.Request, publicDataLen int) {
	bodyKind := "none"
	bodyLen := 0
	switch body := req.GetBody().(type) {
	case *confhttptypes.Request_BodyString:
		bodyKind = "string"
		bodyLen = len(body.BodyString)
	case *confhttptypes.Request_BodyBytes:
		bodyKind = "bytes"
		bodyLen = len(body.BodyBytes)
	}

	timeout := ""
	if req.GetTimeout() != nil {
		timeout = req.GetTimeout().AsDuration().String()
	}

	reqLog.Infow("decoded publicData",
		"event", "PUBLIC_DATA",
		"appID", types.AppIDConfidentialHTTP,
		"publicDataLen", publicDataLen,
		"publicDataType", "confidential_http_request",
		"url", req.GetUrl(),
		"method", req.GetMethod(),
		"bodyKind", bodyKind,
		"bodyLen", bodyLen,
		"headerNames", slices.Sorted(maps.Keys(req.GetMultiHeaders())),
		"templatePublicValueKeys", slices.Sorted(maps.Keys(req.GetTemplatePublicValues())),
		"customRootCACertPEMLen", len(req.GetCustomRootCaCertPem()),
		"timeout", timeout,
		"encryptOutput", req.GetEncryptOutput())
}

func logWorkflowPublicData(
	reqLog cllogger.SugaredLogger,
	execution *confworkflowtypes.WorkflowExecution,
	publicDataLen int,
) {
	executeRequestConfigLen := 0
	var maxResponseSize uint64
	fields := []any{
		"event", "PUBLIC_DATA",
		"appID", types.AppIDConfidentialWorkflows,
		"publicDataLen", publicDataLen,
		"publicDataType", "workflow_execution",
		"workflowID", execution.GetWorkflowId(),
		"executionID", execution.GetExecutionId(),
		"owner", execution.GetOwner(),
		"orgID", execution.GetOrgId(),
		"binaryURL", execution.GetBinaryUrl(),
		"binaryHash", hex.EncodeToString(execution.GetBinaryHash()),
		"requirementsPresent", execution.GetRequirements() != nil,
		"restrictionsPresent", execution.GetRestrictions() != nil,
	}

	if execReq := execution.GetSdkExecuteRequest(); execReq != nil {
		executeRequestConfigLen = len(execReq.GetConfig())
		maxResponseSize = execReq.GetMaxResponseSize()
		switch req := execReq.GetRequest().(type) {
		case *sdkpb.ExecuteRequest_Trigger:
			fields = append(fields, "triggerID", req.Trigger.GetId())
		case *sdkpb.ExecuteRequest_PreHook:
			fields = append(fields, "triggerID", req.PreHook.GetId())
		}
	}

	fields = append(fields,
		"executeRequestKind", workflowRequestKind(execution),
		"executeRequestConfigLen", executeRequestConfigLen,
		"maxResponseSize", maxResponseSize)
	reqLog.Infow("decoded publicData", fields...)
}

func logHTTPResponseOutput(reqLog cllogger.SugaredLogger, resp *confhttptypes.Response, outputLen int) {
	reqLog.Infow("decoded response output",
		"event", "RESPONSE_DATA",
		"appID", types.AppIDConfidentialHTTP,
		"outputLen", outputLen,
		"responseType", "confidential_http_response",
		"statusCode", resp.GetStatusCode(),
		"bodyLen", len(resp.GetBody()),
		"headerNames", slices.Sorted(maps.Keys(resp.GetMultiHeaders())))
}

func logWorkflowResponseOutput(
	reqLog cllogger.SugaredLogger,
	resp *confworkflowtypes.ConfidentialWorkflowResponse,
	outputLen int,
) {
	sdkResult := resp.GetSdkExecutionResult()
	reqLog.Infow("decoded response output",
		"event", "RESPONSE_DATA",
		"appID", types.AppIDConfidentialWorkflows,
		"outputLen", outputLen,
		"responseType", "workflow_execution_result",
		"resultKind", workflowResultKind(sdkResult),
		"sdkResultPresent", sdkResult != nil,
		"executionResultLen", len(resp.GetExecutionResult()),
		"errorLen", len(sdkResult.GetError()))
}

func logPublicDataDecodeError(reqLog cllogger.SugaredLogger, appID string, publicDataLen int, err error) {
	reqLog.Warnw("failed to decode publicData",
		"event", "PUBLIC_DATA_DECODE_ERR",
		"appID", appID,
		"publicDataLen", publicDataLen,
		"error", err)
}

func logResponseOutputDecodeError(reqLog cllogger.SugaredLogger, appID string, outputLen int, err error) {
	reqLog.Warnw("failed to decode response output",
		"event", "RESPONSE_DATA_DECODE_ERR",
		"appID", appID,
		"outputLen", outputLen,
		"error", err)
}
