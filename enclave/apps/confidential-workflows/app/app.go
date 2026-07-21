package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"google.golang.org/protobuf/proto"
)

// confidentialWorkflowsApp is an EnclaveApp that executes CRE workflow WASM binaries inside a TEE.
//
// logger is for in-enclave diagnostics only: this app, its enclaveExecutionHelper,
// and the chainlink-common WASM host module (host.ModuleConfig.Logger, which
// the host runtime uses for its own bookkeeping warnings/errors during module
// lifecycle). It is NOT the WASM runtime.Logger() that workflow authors call;
// that one flows through ExecutionHelper.EmitUserLog (currently a no-op stub,
// see PRIV-443).
type confidentialWorkflowsApp struct {
	logger              logger.Logger
	fetcher             *BinaryFetcher
	httpFetcher         *httpfetch.Fetcher
	requirementsHandler host.RequirementsHandler
	tpe                 sdkpb.TeeType

	// limiter bounds concurrent executions so a burst can't exhaust the fixed
	// enclave memory and wedge the VM. Unbounded unless WithMaxConcurrentExecutions
	// is set (the nitro entrypoint derives a limit from enclave memory).
	limiter *executionLimiter

	// Runtime config + secrets injected via InjectSettings (host over vsock). A
	// Nitro EIF is measured (PCR), so environment-specific endpoints can't be
	// baked in; the storage endpoint, the ed25519 storage key, and the gateway
	// URL all arrive at runtime. mu guards everything below.
	mu                sync.Mutex
	storageServiceURL string // startup default (fake/tests); an injected URL overrides
	storageServiceTLS bool
	storageFetcher    RawFetcher
	dispatcher        RemoteDispatcher                         // nil = local mode
	dispatcherFactory func(gatewayURL string) RemoteDispatcher // builds dispatcher on first GatewayURL injection
	lastConfig        types.EnclaveConfig
	haveConfig        bool
}

var _ types.EnclaveApp = (*confidentialWorkflowsApp)(nil)

// Option configures optional behavior for the confidential workflows app.
type Option func(*confidentialWorkflowsApp)

// WithRemoteDispatcher enables remote dynamic secrets and remote capability
// dispatch with a dispatcher built up-front. Used by tests that already know the
// gateway endpoint; the nitro/fake mains use WithRemoteDispatcherFactory since
// the gateway URL is injected at runtime.
func WithRemoteDispatcher(d RemoteDispatcher) Option {
	return func(a *confidentialWorkflowsApp) {
		a.dispatcher = d
	}
}

// WithRemoteDispatcherFactory supplies a builder that constructs the remote
// dispatcher from a Gateway URL injected at runtime (via InjectSettings). The
// measured EIF can't bake the gateway URL, so the nitro/fake mains pass a
// factory here and the dispatcher is created when the host injects the URL.
func WithRemoteDispatcherFactory(f func(gatewayURL string) RemoteDispatcher) Option {
	return func(a *confidentialWorkflowsApp) {
		a.dispatcherFactory = f
	}
}

// WithHTTPFetcher overrides the default httpfetch.Fetcher used to service
// http-actions capability calls from inside the enclave. Intended for tests
// that need a looser policy (e.g. permitting localhost).
func WithHTTPFetcher(f *httpfetch.Fetcher) Option {
	return func(a *confidentialWorkflowsApp) {
		a.httpFetcher = f
	}
}

// WithStorageService sets the CRE storage-service gRPC address (and whether to
// use TLS) that the enclave fetches workflow binaries from. The ed25519 key that
// authenticates to it is supplied separately via InjectSettings.
func WithStorageService(url string, tls bool) Option {
	return func(a *confidentialWorkflowsApp) {
		a.storageServiceURL = url
		a.storageServiceTLS = tls
	}
}

// WithMaxConcurrentExecutions bounds concurrent Execute calls to n; n <= 0 means
// unbounded. The nitro entrypoint derives n from enclave memory so a burst of
// executions can't exhaust the fixed enclave memory and wedge the VM. fake/local
// runs and tests leave it unbounded.
func WithMaxConcurrentExecutions(n int64) Option {
	return func(a *confidentialWorkflowsApp) {
		a.limiter = newExecutionLimiter(n)
	}
}

// InjectSettings receives runtime config + secrets injected by the host over
// vsock and wires up whatever arrived: the storage fetcher (once both the
// endpoint and the ed25519 key are known) and, on the first gateway URL, the
// remote dispatcher (via the factory). Fetcher tunables (max binary size, fetch
// timeout, cache size) are applied when present, falling back to the defaults
// in constants.go. An injected StorageServiceURL overrides the startup default.
// Safe to call again (e.g. key rotation).
func (a *confidentialWorkflowsApp) InjectSettings(req types.SettingsRequest) error {
	a.fetcher.SetMaxCacheBytes(int(req.MaxCacheBytes))

	a.mu.Lock()
	if req.StorageServiceURL != "" {
		a.storageServiceURL = req.StorageServiceURL
		a.storageServiceTLS = req.StorageServiceTLS
	}
	url, tls := a.storageServiceURL, a.storageServiceTLS
	a.mu.Unlock()

	if req.StorageKey != "" && url != "" {
		fetcher, pub, err := NewStorageFetcher(url, tls, req.StorageKey, req.MaxBinarySize, req.BinaryFetchTimeout, a.logger)
		if err != nil {
			return fmt.Errorf("building storage fetcher: %w", err)
		}
		a.mu.Lock()
		old := a.storageFetcher
		a.storageFetcher = fetcher
		a.mu.Unlock()
		if old != nil {
			if cerr := old.Close(); cerr != nil {
				a.logger.Warnf("[app] closing previous storage fetcher: %v", cerr)
			}
		}
		a.logger.Infof("[app] storage credentials set (pubkey=%x, storage=%s)", pub, url)
	}

	if req.GatewayURL != "" {
		a.mu.Lock()
		if a.dispatcher == nil && a.dispatcherFactory != nil {
			d := a.dispatcherFactory(req.GatewayURL)
			if a.haveConfig {
				// Config may have arrived before credentials; apply it now so the
				// freshly built dispatcher has the vault's MasterPublicKey/T.
				d.SetConfig(a.lastConfig)
			}
			a.dispatcher = d
			a.logger.Infof("[app] remote dispatch enabled (gateway=%s)", req.GatewayURL)
		}
		a.mu.Unlock()
	}
	return nil
}

// OnConfigUpdate propagates the enclave config to the remote dispatcher so it
// has the vault's MasterPublicKey and threshold for TDH2 decryption. It also
// stores the config so a dispatcher built later (credentials can arrive after
// config) picks it up in InjectSettings.
func (a *confidentialWorkflowsApp) OnConfigUpdate(config types.EnclaveConfig) {
	a.mu.Lock()
	a.lastConfig = config
	a.haveConfig = true
	d := a.dispatcher
	a.mu.Unlock()
	if d != nil {
		d.SetConfig(config)
		a.logger.Infof("[app] dispatcher config updated: MasterPublicKey=%d bytes, T=%d", len(config.MasterPublicKey), config.T)
	}
}

func NewConfidentialWorkflowsApp(tpe sdkpb.TeeType, lggr logger.Logger, _ types.HTTPClient, opts ...Option) types.EnclaveApp {
	a := &confidentialWorkflowsApp{
		logger:      lggr,
		fetcher:     NewBinaryFetcher(lggr),
		httpFetcher: httpfetch.NewFetcher(httpfetch.DefaultPolicy()),
		tpe:         tpe,
		limiter:     newExecutionLimiter(0), // unbounded unless an option overrides
	}
	for _, opt := range opts {
		opt(a)
	}
	a.requirementsHandler.Tee = a.validTee

	return a
}

func (a *confidentialWorkflowsApp) Execute(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter, rawSignedRequests ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
	// Bound concurrent executions so a burst can't exhaust the fixed enclave
	// memory and wedge the VM. Fail fast when full rather than piling on.
	if !a.limiter.tryAcquire() {
		emitter.Emit("execution_rejected_at_capacity", map[string]any{"max_concurrent": a.limiter.capacity()})
		return nil, &types.ExecuteError{
			Error: "enclave at capacity: too many concurrent executions",
			Code:  http.StatusTooManyRequests,
		}
	}
	defer a.limiter.release()

	if appID != types.AppIDConfidentialWorkflows {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("invalid app ID: expected %s, got %s", types.AppIDConfidentialWorkflows, appID),
			Code:  http.StatusBadRequest,
		}
	}

	var execution confworkflowtypes.WorkflowExecution
	if err := proto.Unmarshal(inputData, &execution); err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("unable to unmarshal request data: %s", err.Error()),
			Code:  http.StatusBadRequest,
		}
	}

	if execution.WorkflowId == "" {
		return nil, &types.ExecuteError{
			Error: "workflow_id is required",
			Code:  http.StatusBadRequest,
		}
	}

	if execution.BinaryUrl == "" {
		return nil, &types.ExecuteError{
			Error: "binary_url is required",
			Code:  http.StatusBadRequest,
		}
	}

	if len(execution.BinaryHash) == 0 {
		return nil, &types.ExecuteError{
			Error: "binary_hash is required",
			Code:  http.StatusBadRequest,
		}
	}

	if execution.SdkExecuteRequest == nil {
		return nil, &types.ExecuteError{
			Error: "execute_request is required",
			Code:  http.StatusBadRequest,
		}
	}

	emitter.Emit("workflow_execute_started", map[string]any{
		"workflow_id": execution.WorkflowId,
	})

	// Fetch (and cache) the WASM binary directly from the CRE storage service.
	// binary_url is the storage-service artifact locator; the storage fetcher
	// authenticates the DownloadArtifact call with the injected ed25519 key and
	// returns the bytes, which BinaryFetcher verifies against binary_hash.
	a.mu.Lock()
	sf := a.storageFetcher
	dispatcher := a.dispatcher
	a.mu.Unlock()
	binary, err := a.fetcher.Fetch(context.Background(), execution.BinaryUrl, execution.BinaryHash, sf)
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("fetching binary: %s", err.Error()),
			Code:  http.StatusBadGateway,
		}
	}

	helper := &enclaveExecutionHelper{
		requestID:        requestID,
		workflowID:       execution.WorkflowId,
		owner:            execution.GetOwner(),
		executionID:      execution.GetExecutionId(),
		orgID:            execution.GetOrgId(),
		signedRequests:   rawSignedRequests,
		logger:           a.logger,
		emitter:          emitter,
		remoteDispatcher: dispatcher,
		httpFetcher:      a.httpFetcher,
	}

	if !host.CheckRequirements(context.Background(), a.requirementsHandler, execution.Requirements) {
		reqSerialized, _ := json.Marshal(execution.Requirements)
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("this TEE doesn't meet the requirements %s of the workflow: %s", reqSerialized, execution.WorkflowId),
			Code:  http.StatusBadRequest,
		}
	}

	// Execute the WASM binary with the deserialized ExecuteRequest.
	// The fetched binary is brotli-compressed.
	// chainlink-common's WASM host applies workflow-scoped resource limits (e.g.
	// concurrent capability calls) keyed off CRE metadata in the context.
	execCtx := contexts.WithCRE(context.Background(), contexts.CRE{
		Org:      execution.GetOrgId(),
		Owner:    execution.GetOwner(),
		Workflow: execution.WorkflowId,
	})
	result, err := executeWasm(execCtx, a.logger, binary, execution.SdkExecuteRequest, true, helper)
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("executing wasm: %s", err.Error()),
			Code:  http.StatusInternalServerError,
		}
	}

	// Wrap the serialized ExecutionResult in a ConfidentialWorkflowResponse.
	// The framework's base_action.go unmarshals enclave output as the TOutput
	// type parameter, which for this capability is ConfidentialWorkflowResponse.
	cwResp := &confworkflowtypes.ConfidentialWorkflowResponse{SdkExecutionResult: result}
	cwRespBytes, err := proto.Marshal(cwResp)
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("marshalling workflow response: %s", err.Error()),
			Code:  http.StatusInternalServerError,
		}
	}

	return cwRespBytes, nil
}

// TEEs can't tell what region they are in, so we just check the TEE type and rely on the DON to ensure it's sending to the right place
func (a *confidentialWorkflowsApp) validTee(_ context.Context, tee *sdkpb.Tee) bool {
	switch teet := tee.Item.(type) {
	case *sdkpb.Tee_TeeTypesAndRegions:
		for _, t := range teet.TeeTypesAndRegions.TeeTypeAndRegions {
			if t.Type == a.tpe {
				return true
			}
		}
		return false
	case *sdkpb.Tee_AnyRegions:
		return true
	default:
		return false
	}
}
