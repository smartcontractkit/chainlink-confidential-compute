package framework

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	eventsv2 "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
)

// PRIV-542: This is best-effort so far, these may be fixed to connect properly to the frontend.

// Capability lifecycle Beholder message coordinates, matching the DON-mode workflow
// engine so enclave capability calls land in the same executions pipeline.
const (
	capabilityStartedSchemaV2  = "/cre-events-capability-started/v2"
	capabilityFinishedSchemaV2 = "/cre-events-capability-finished/v2"
	capabilityStartedEntityV2  = "workflows.v2.CapabilityExecutionStarted"
	capabilityFinishedEntityV2 = "workflows.v2.CapabilityExecutionFinished"
)

// emitCapabilityStarted re-emits an enclave "capability_started" event as a v2
// CapabilityExecutionStarted Beholder message, the channel the executions UI reads.
func emitCapabilityStarted(ctx context.Context, lggr logger.Logger, meta capabilities.RequestMetadata, capabilityID, method string, stepRef int32) {
	event := &eventsv2.CapabilityExecutionStarted{
		CreInfo:             creInfoFromMeta(meta),
		Workflow:            workflowKeyFromMeta(meta),
		WorkflowExecutionID: meta.WorkflowExecutionID,
		Timestamp:           time.Now().Format(time.RFC3339Nano),
		CapabilityID:        capabilityID,
		StepRef:             stepRef,
		Method:              method,
	}
	emitProtoEvent(ctx, lggr, event, capabilityStartedSchemaV2, capabilityStartedEntityV2)
}

// emitCapabilityFinished re-emits an enclave "capability_finished" event as a v2
// CapabilityExecutionFinished Beholder message. The enclave reports a success bool;
// it maps to the SUCCEEDED/FAILED execution status the UI expects.
func emitCapabilityFinished(ctx context.Context, lggr logger.Logger, meta capabilities.RequestMetadata, capabilityID, method string, stepRef int32, success bool, errMsg string) {
	status := eventsv2.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED
	if !success {
		status = eventsv2.ExecutionStatus_EXECUTION_STATUS_FAILED
	}
	event := &eventsv2.CapabilityExecutionFinished{
		CreInfo:             creInfoFromMeta(meta),
		Workflow:            workflowKeyFromMeta(meta),
		WorkflowExecutionID: meta.WorkflowExecutionID,
		Timestamp:           time.Now().Format(time.RFC3339Nano),
		CapabilityID:        capabilityID,
		StepRef:             stepRef,
		Status:              status,
		Error:               errMsg,
		Method:              method,
	}
	emitProtoEvent(ctx, lggr, event, capabilityFinishedSchemaV2, capabilityFinishedEntityV2)
}
