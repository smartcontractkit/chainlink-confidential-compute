package framework

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	eventsv2 "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
)

// PRIV-542: This is best-effort so far, these may be fixed to connect properly to the frontend.

// User-log Beholder message coordinates, matching the DON-mode workflow engine so
// enclave user logs land in the same logs pipeline as regular workflows.
const (
	userLogSchemaV2 = "/cre-events-user-logs/v2"
	userLogEntityV2 = "workflows.v2.WorkflowUserLog"
)

// emitUserLog re-emits an enclave "user_log" event as a v2 WorkflowUserLog Beholder
// message, the channel the logs UI reads. The message text comes from the enclave
// response; the workflow/DON coordinates come from the host's request metadata.
func emitUserLog(ctx context.Context, lggr logger.Logger, meta capabilities.RequestMetadata, msg string) {
	event := &eventsv2.WorkflowUserLog{
		CreInfo:             creInfoFromMeta(meta),
		Workflow:            workflowKeyFromMeta(meta),
		WorkflowExecutionID: meta.WorkflowExecutionID,
		Timestamp:           time.Now().Format(time.RFC3339Nano),
		Msg:                 msg,
		Labels:              map[string]string{},
	}
	emitProtoEvent(ctx, lggr, event, userLogSchemaV2, userLogEntityV2)
}
