package framework

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/confidential-compute/types"
	framework "github.com/smartcontractkit/confidential-compute/types/frameworktypes"
	"google.golang.org/protobuf/proto"
)

// ExecutorInput must be satisfied by all capabilities running on the Confidential Compute Framework.
// The `GetInput` function is satisfied by any proto struct with an `Input` field.
// The GetVaultDonSecrets method may be satisfied by adding the `SecretIdentifier` struct
// available in the `github.com/smartcontractkit/confidential-compute/types/frameworktypes` package.
type ExecutorInput interface {
	GetInput() proto.Message
	GetVaultDonSecrets() []*framework.SecretIdentifier
}

type ConfidentialAction[TInput ExecutorInput, TOutput proto.Message] interface {
	Start(ctx context.Context) error
	Close() error
	HealthReport() map[string]error
	Name() string
	Description() string
	Ready() error
	Initialise(ctx context.Context, dependencies core.StandardCapabilitiesDependencies) error
	// EnsureExecutorReady triggers the executor's one-time setup (config
	// parsing, API key decryption, enclave pool population). Idempotent and
	// concurrency-safe. Callers that need GetEnclaves to return a populated
	// list (e.g. ProvidedTees) should call this first, since the standard
	// capability lifecycle does not pre-load enclaves: the chainlink
	// LocalRegistry is empty at Initialise time, so a load there would fail.
	EnsureExecutorReady(ctx context.Context) error
	Execute(ctx context.Context, metadata capabilities.RequestMetadata, input TInput) (*capabilities.ResponseAndMetadata[TOutput], error)
	GetEnclaves() []types.Enclave
}

// ConfidentialAction is the generic capability definition that supports interactions with the
// Vault DON and an enclave pool, and should be implemented by all capabilities using the Confidential Compute Framework.
// It allows for any proto message to be used as output, and for any proto message implementing the `ExecutorInput`
// interface to be used as input.
type baseConfidentialAction[TInput ExecutorInput, TOutput proto.Message] struct {
	lggr                       logger.SugaredLogger
	executor                   Executor
	name                       string
	description                string
	capabilityID               string
	confidentialComputeVersion string
	limitsFactory              limits.Factory
	emptyOutputCreator         func() TOutput
}

var _ ConfidentialAction[ExecutorInput, proto.Message] = (*baseConfidentialAction[ExecutorInput, proto.Message])(nil)

func NewConfidentialAction[TInput ExecutorInput, TOutput proto.Message](
	lggr logger.Logger,
	name string,
	description string,
	capabilityID string,
	confidentialComputeVersion string,
	limitsFactory limits.Factory,
	outputCreator func() TOutput,
) ConfidentialAction[TInput, TOutput] {
	return &baseConfidentialAction[TInput, TOutput]{
		lggr:                       logger.Sugared(logger.Named(lggr, name)),
		name:                       name,
		description:                description,
		capabilityID:               capabilityID,
		confidentialComputeVersion: confidentialComputeVersion,
		limitsFactory:              limitsFactory,
		emptyOutputCreator:         outputCreator,
	}
}

func (a *baseConfidentialAction[TInput, TOutput]) Initialise(
	ctx context.Context,
	dependencies core.StandardCapabilitiesDependencies) error {
	a.lggr.Debugf("Initialising %s", a.name)
	a.lggr.Debugf("Config: %s", dependencies.Config)

	a.executor = NewRealExecutor(a.lggr, dependencies, a.capabilityID, a.confidentialComputeVersion, a.limitsFactory)

	return a.Start(ctx)
}

func (a *baseConfidentialAction[TInput, TOutput]) Execute(ctx context.Context, metadata capabilities.RequestMetadata, input TInput) (*capabilities.ResponseAndMetadata[TOutput], error) {
	a.lggr.Debugf("Received request with metadata: %v", metadata)

	secrets := input.GetVaultDonSecrets() // use the "enforced" method from the ExecutorInput interface

	opts := proto.MarshalOptions{
		Deterministic: true,
	}
	protoBytes, err := opts.Marshal(input.GetInput())
	if err != nil {
		return nil, err
	}

	resultBytes, err := a.executor.Execute(ctx, protoBytes, secrets, metadata)
	if err != nil {
		return nil, err
	}

	output := a.emptyOutputCreator()
	err = proto.Unmarshal(resultBytes, output)
	if err != nil {
		return nil, err
	}

	responseAndMetadata := capabilities.ResponseAndMetadata[TOutput]{
		Response:         output,
		ResponseMetadata: capabilities.ResponseMetadata{},
	}
	return &responseAndMetadata, nil
}

func (a *baseConfidentialAction[TInput, TOutput]) Start(ctx context.Context) error {
	a.lggr.Debug("Service starting...")
	return nil
}

func (a *baseConfidentialAction[TInput, TOutput]) Close() error {
	a.lggr.Debug("Service closing...")
	if a.executor != nil {
		return a.executor.Close()
	}
	return nil
}

func (a *baseConfidentialAction[TInput, TOutput]) HealthReport() map[string]error {
	return map[string]error{a.Name(): nil}
}

func (a *baseConfidentialAction[TInput, TOutput]) Ready() error {
	return nil
}

func (a *baseConfidentialAction[TInput, TOutput]) Name() string {
	return a.name
}

func (a *baseConfidentialAction[TInput, TOutput]) Description() string {
	return a.description
}

func (a *baseConfidentialAction[TInput, TOutput]) EnsureExecutorReady(ctx context.Context) error {
	return a.executor.Initialize(ctx)
}

func (a *baseConfidentialAction[TInput, TOutput]) GetEnclaves() []types.Enclave {
	return a.executor.GetEnclaves()
}
