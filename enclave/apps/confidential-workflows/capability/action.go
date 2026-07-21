package capability

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/types/frameworktypes"

	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow/server"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

const ServiceName = "ConfidentialWorkflowsCapabilityService"
const ServiceDescription = "Confidential Workflows Capability Service"

var _ server.ClientCapability = (*ConfidentialWorkflowAction)(nil)

// EnclaveActionInputAdapter adapts the proto type to the framework interface
type EnclaveActionInputAdapter struct {
	*confworkflowtypes.ConfidentialWorkflowRequest
}

func (a *EnclaveActionInputAdapter) GetInput() proto.Message {
	return a.Execution
}

// GetVaultDonSecrets always returns nil. Confidential workflows fetch secrets
// dynamically from the enclave at runtime; no upfront declaration or prefetch.
func (a *EnclaveActionInputAdapter) GetVaultDonSecrets() []*frameworktypes.SecretIdentifier {
	return nil
}

type ConfidentialWorkflowAction struct {
	framework.ConfidentialAction[*EnclaveActionInputAdapter, *confworkflowtypes.ConfidentialWorkflowResponse]
	lggr logger.SugaredLogger
}

func (a *ConfidentialWorkflowAction) Execute(ctx context.Context, metadata capabilities.RequestMetadata, input *confworkflowtypes.ConfidentialWorkflowRequest) (*capabilities.ResponseAndMetadata[*confworkflowtypes.ConfidentialWorkflowResponse], caperrors.Error) {
	if input.Execution == nil {
		// Missing required input field is a workflow-author bug, not infrastructure failure.
		// Classify as OriginUser so the workflow engine routes to _user_errors, not _failures.
		errStr := "execution field is required"
		a.lggr.Errorw(errStr)
		return nil, caperrors.NewPublicUserError(errors.New(errStr), caperrors.InvalidArgument)
	}
	if len(input.VaultDonSecrets) > 0 {
		// Using an unsupported request field is also a workflow-author bug.
		errStr := "vault_don_secrets is not supported; secrets are fetched dynamically by the enclave at runtime"
		a.lggr.Errorw(errStr)
		return nil, caperrors.NewPublicUserError(errors.New(errStr), caperrors.InvalidArgument)
	}
	ctx = metadata.ContextWithCRE(ctx)
	out, err := a.ConfidentialAction.Execute(ctx, metadata, &EnclaveActionInputAdapter{input})
	if err != nil {
		// Preserve typed errors from the underlying framework (matches confidential-http's
		// action.go pattern). Without this, a typed OriginUser error from the framework gets
		// downgraded back to OriginSystem on the way out.
		var capErr caperrors.Error
		if errors.As(err, &capErr) {
			return nil, capErr
		}
		return nil, caperrors.NewError(err, caperrors.VisibilityPrivate, caperrors.OriginSystem, caperrors.Internal)
	}
	return out, nil
}

func (a *ConfidentialWorkflowAction) ProvidedTees(ctx context.Context, metadata capabilities.RequestMetadata, input *emptypb.Empty) (*capabilities.ResponseAndMetadata[*confworkflowtypes.ProvidedTeesResponse], caperrors.Error) {
	// Trigger executor setup before reading enclaves. Without this the executor
	// is lazy-initialised on first Execute, so an early ProvidedTees would see
	// an empty enclave list. Chainlink's ConfidentialModule.Tee caches the
	// resulting matcher via sync.Once, so an empty first response permanently
	// rejects every Tee requirement and the workflow engine fails subscribe.
	if err := a.EnsureExecutorReady(ctx); err != nil {
		a.lggr.Errorw("ProvidedTees: failed to ensure executor ready", "err", err)
		return nil, caperrors.NewError(err, caperrors.VisibilityPrivate, caperrors.OriginSystem, caperrors.Internal)
	}
	grouped := make(map[sdkpb.TeeType][]string)
	for _, enc := range a.GetEnclaves() {
		teeType := framework.MapEnclaveType(enc.EnclaveType)
		if _, ok := grouped[teeType]; !ok {
			grouped[teeType] = nil
		}
		if enc.Region != "" {
			grouped[teeType] = append(grouped[teeType], enc.Region)
		}
	}

	var tees []*sdkpb.TeeTypeAndRegions
	for teeType, regions := range grouped {
		tees = append(tees, &sdkpb.TeeTypeAndRegions{
			Type:    teeType,
			Regions: regions,
		})
	}

	return &capabilities.ResponseAndMetadata[*confworkflowtypes.ProvidedTeesResponse]{
		Response: &confworkflowtypes.ProvidedTeesResponse{Tee: tees},
	}, nil
}

func (a *ConfidentialWorkflowAction) Initialise(ctx context.Context, dependencies core.StandardCapabilitiesDependencies) error {
	a.lggr.Debugf("Initialising %s", ServiceName)
	return a.ConfidentialAction.Initialise(ctx, dependencies)
}

func NewService(lggr logger.Logger, limitsFactory limits.Factory) *ConfidentialWorkflowAction {
	return &ConfidentialWorkflowAction{
		ConfidentialAction: framework.NewConfidentialAction[*EnclaveActionInputAdapter](
			lggr,
			ServiceName,
			ServiceDescription,
			cctypes.AppIDConfidentialWorkflows,
			cctypes.ServiceConfidentialComputeVersion,
			limitsFactory,
			func() *confworkflowtypes.ConfidentialWorkflowResponse {
				return &confworkflowtypes.ConfidentialWorkflowResponse{}
			},
		),
		lggr: logger.Sugared(logger.Named(lggr, ServiceName)),
	}
}
