package main

import (
	"testing"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestWorkflowExecutionMetadataRequestKinds(t *testing.T) {
	tests := []struct {
		name        string
		request     *sdkpb.ExecuteRequest
		requestKind string
	}{
		{name: "missing request", requestKind: "unset"},
		{name: "unset request", request: &sdkpb.ExecuteRequest{}, requestKind: "unset"},
		{
			name: "subscribe",
			request: &sdkpb.ExecuteRequest{
				Request: &sdkpb.ExecuteRequest_Subscribe{Subscribe: &emptypb.Empty{}},
			},
			requestKind: "subscribe",
		},
		{
			name: "trigger",
			request: &sdkpb.ExecuteRequest{
				Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 7}},
			},
			requestKind: "trigger",
		},
		{
			name: "pre-hook",
			request: &sdkpb.ExecuteRequest{
				Request: &sdkpb.ExecuteRequest_PreHook{PreHook: &sdkpb.Trigger{Id: 8}},
			},
			requestKind: "pre_hook",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := workflowExecutionMetadata(&confworkflowtypes.WorkflowExecution{
				WorkflowId:        "workflow-id",
				SdkExecuteRequest: test.request,
			})

			assert.Equal(t, executionMetadata{
				appID:       types.AppIDConfidentialWorkflows,
				workflowID:  "workflow-id",
				requestKind: test.requestKind,
			}, metadata)
		})
	}
}
