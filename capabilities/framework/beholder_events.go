package framework

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	eventsv2 "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
	"google.golang.org/protobuf/proto"
)

// PRIV-542: This is best-effort so far, these may be fixed to connect properly to the frontend.

// eventDomain is the Beholder domain shared by all workflow-engine events.
const eventDomain = "platform"

// creInfoFromMeta builds the v2 CreInfo carried on every workflow-engine event
// from the host's request metadata.
func creInfoFromMeta(meta capabilities.RequestMetadata) *eventsv2.CreInfo {
	return &eventsv2.CreInfo{
		DonID:                   int32(meta.WorkflowDonID),
		WorkflowRegistryAddress: meta.WorkflowRegistryAddress,
		WorkflowRegistryChain:   meta.WorkflowRegistryChainSelector,
		EngineVersion:           meta.EngineVersion,
	}
}

// workflowKeyFromMeta builds the v2 WorkflowKey carried on every workflow-engine
// event from the host's request metadata.
func workflowKeyFromMeta(meta capabilities.RequestMetadata) *eventsv2.WorkflowKey {
	return &eventsv2.WorkflowKey{
		WorkflowOwner:  meta.WorkflowOwner,
		WorkflowName:   meta.WorkflowName,
		WorkflowID:     meta.WorkflowID,
		OrganizationID: meta.OrgID,
	}
}

// emitProtoEvent marshals a workflow-engine proto message and emits it on the
// node's global Beholder emitter with the given schema and entity, the same
// client and coordinates the DON-mode engine uses so enclave events land in the
// same pipeline.
func emitProtoEvent(ctx context.Context, lggr logger.Logger, event proto.Message, schema, entity string) {
	body, err := proto.Marshal(event)
	if err != nil {
		lggr.Errorw("failed to marshal beholder event", "entity", entity, "error", err)
		return
	}
	if err := beholder.GetEmitter().Emit(ctx, body,
		"beholder_data_schema", schema,
		"beholder_domain", eventDomain,
		"beholder_entity", entity); err != nil {
		lggr.Errorw("failed to emit beholder event", "entity", entity, "error", err)
	}
}

// detailInt32 reads an integer field from an enclave event's Details map. Details
// is JSON-transported, so numbers arrive as float64.
func detailInt32(d map[string]any, key string) int32 {
	switch v := d[key].(type) {
	case float64:
		return int32(v)
	case int32:
		return v
	case int:
		return int32(v)
	}
	return 0
}
