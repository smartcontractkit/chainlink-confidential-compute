package capability

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/types/frameworktypes"

	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	confhttptypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp/server"
)

const ServiceName = "ConfidentialHTTPCapabilityService"
const ServiceDescription = "Confidential HTTP Capability Service"

var _ server.ClientCapability = (*ConfidentialHttpAction)(nil)

// EnclaveActionInputAdapter adapts the proto type to the framework interface
type EnclaveActionInputAdapter struct {
	*confhttptypes.ConfidentialHTTPRequest
}

func (a *EnclaveActionInputAdapter) GetInput() proto.Message {
	return a.Request
}

// Convert []*confhttptypes.SecretIdentifier to []*frameworktypes.SecretIdentifier
func (a *EnclaveActionInputAdapter) GetVaultDonSecrets() []*frameworktypes.SecretIdentifier {
	secrets := make([]*frameworktypes.SecretIdentifier, len(a.VaultDonSecrets))
	for i, s := range a.VaultDonSecrets {
		secrets[i] = &frameworktypes.SecretIdentifier{
			Key:       s.Key,
			Namespace: s.Namespace,
			Owner:     s.Owner,
		}
	}
	return secrets
}

type ConfidentialHttpAction struct {
	framework.ConfidentialAction[*EnclaveActionInputAdapter, *confhttptypes.HTTPResponse]
	lggr          logger.SugaredLogger
	limitsFactory limits.Factory
	validator     *Validator
}

func (a *ConfidentialHttpAction) SendRequest(ctx context.Context, metadata capabilities.RequestMetadata, input *confhttptypes.ConfidentialHTTPRequest) (*capabilities.ResponseAndMetadata[*confhttptypes.HTTPResponse], caperrors.Error) {
	if a.validator == nil {
		errStr := "validator is not initialized"
		a.lggr.Error(errStr)
		return nil, caperrors.NewError(errors.New(errStr), caperrors.VisibilityPrivate, caperrors.OriginSystem, caperrors.Internal)
	}
	ctx = metadata.ContextWithCRE(ctx)
	err := a.validator.ValidateRequest(ctx, input)
	if err != nil {
		// Input validation failures (request size > limit, response size > limit, connection
		// timeout > bound, etc.) are workflow-author configuration issues, not infrastructure
		// failures. Classify as OriginUser so the workflow engine routes them to
		// platform_engine_capabilities_user_errors instead of _failures, taking these off the
		// system-error alert path. The validator already prefixes the error with
		// "input validation failed: ", so pass err through directly to avoid double-prefixing.
		a.lggr.Errorw("input validation failed", "error", err)
		return nil, caperrors.NewPublicUserError(err, caperrors.InvalidArgument)
	}
	out, err := a.Execute(ctx, metadata, &EnclaveActionInputAdapter{input})
	if err != nil {
		var capErr caperrors.Error
		if errors.As(err, &capErr) {
			return nil, capErr
		}
		return nil, caperrors.NewError(err, caperrors.VisibilityPrivate, caperrors.OriginSystem, caperrors.Internal)
	}

	return out, nil
}

func (a *ConfidentialHttpAction) Initialise(ctx context.Context, dependencies core.StandardCapabilitiesDependencies) error {
	a.lggr.Debugf("Initialising %s. config: %s", ServiceName, dependencies.Config)

	v, err := NewValidator(a.lggr, a.limitsFactory)
	if err != nil {
		return err
	}
	a.validator = v
	return a.ConfidentialAction.Initialise(ctx, dependencies)
}

func (a *ConfidentialHttpAction) Close() error {
	if a.validator != nil {
		if err := a.validator.Close(); err != nil {
			a.lggr.Errorw("failed to close validator", "error", err)
		}
	}
	return a.ConfidentialAction.Close()
}

func NewService(lggr logger.Logger, limitsFactory limits.Factory) *ConfidentialHttpAction {
	return &ConfidentialHttpAction{
		ConfidentialAction: framework.NewConfidentialAction[*EnclaveActionInputAdapter](
			lggr,
			ServiceName,
			ServiceDescription,
			cctypes.AppIDConfidentialHTTP,
			cctypes.ServiceConfidentialComputeVersion,
			limitsFactory,
			func() *confhttptypes.HTTPResponse {
				return &confhttptypes.HTTPResponse{}
			},
		),
		lggr:          logger.Sugared(logger.Named(lggr, ServiceName)),
		limitsFactory: limitsFactory,
	}
}
