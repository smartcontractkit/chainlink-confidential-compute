package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
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

	// executionTimeout bounds a single WASM run (nanoseconds; 0 = the WASM
	// host's own default). Injected via InjectSettings, read on every Execute,
	// so it is atomic rather than guarded by mu.
	executionTimeout atomic.Int64

	// gracePeriod is how long a validated execution waits before it starts
	// running (nanoseconds; non-positive = no wait). Same reasoning as above for
	// the atomic.
	gracePeriod atomic.Int64

	// Runtime config + secrets injected via InjectSettings (host over vsock). A
	// Nitro EIF is measured (PCR), so environment-specific endpoints can't be
	// baked in; the storage endpoint, the ed25519 storage key, and the gateway
	// URL all arrive at runtime. mu guards everything below.
	mu                sync.Mutex
	storageServiceURL string // startup default (fake/tests); an injected URL overrides
	storageServiceTLS bool
	storageFetcher    RawFetcher
	storageFactory    StorageFetcherFactory
	dispatcher        RemoteDispatcher        // nil = local mode
	dispatcherFactory RemoteDispatcherFactory // builds dispatcher on first GatewayURL injection
	lastConfig        types.EnclaveConfig
	haveConfig        bool
}

var _ types.EnclaveApp = (*confidentialWorkflowsApp)(nil)

// Config requires explicit transports to prevent direct network access.
type Config struct {
	HTTPFetcher             *httpfetch.Fetcher
	StorageFetcherFactory   StorageFetcherFactory
	RemoteDispatcherFactory RemoteDispatcherFactory
	MaxConcurrentExecutions int64
}

type Option func(*confidentialWorkflowsApp)

type StorageFetcherFactory func(storageURL string, tls bool, privateKey string, maxBytes int64, timeout time.Duration, lggr logger.Logger) (RawFetcher, ed25519.PublicKey, error)

// RemoteDispatcherFactory defers construction until the host injects the gateway URL.
type RemoteDispatcherFactory func(gatewayURL string, timeout time.Duration) (RemoteDispatcher, error)

func storageFetcherFactory(newHTTPClient func() types.HTTPClient) StorageFetcherFactory {
	return func(storageURL string, tls bool, privateKey string, maxBytes int64, timeout time.Duration, lggr logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
		return NewStorageFetcher(
			storageURL, tls, privateKey, maxBytes, timeout, lggr, newHTTPClient(),
		)
	}
}

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
// dispatcher from a Gateway URL and client timeout injected at runtime (via
// InjectSettings). The measured EIF can't bake the gateway URL, so the
// nitro/fake mains pass a factory here and the dispatcher is created when the
// host injects the URL. A non-positive timeout means the caller's own default.
func WithRemoteDispatcherFactory(f RemoteDispatcherFactory) Option {
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

func WithStorageFetcherFactory(factory StorageFetcherFactory) Option {
	return func(a *confidentialWorkflowsApp) {
		a.storageFactory = factory
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

// InjectSettings receives the settings JSON injected by the host over vsock and
// wires up what it carries: the storage fetcher (endpoint + ed25519 key) and, on
// the first injection, the remote dispatcher (via the factory). The required
// fields are asserted before anything is applied, so a deployment that forgot
// one fails the injection instead of running half-configured; see
// WorkflowSettings. Fetcher tunables (max binary size, fetch timeout, cache
// size) and the timeouts (global request, gateway client, workflow execution)
// fall back to the built-in defaults when omitted. Safe to call again (e.g. key
// rotation), as long as the payload stays complete.
func (a *confidentialWorkflowsApp) InjectSettings(raw json.RawMessage) error {
	var req WorkflowSettings
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parsing settings: %w", err)
	}
	if err := req.validate(); err != nil {
		return err
	}

	a.fetcher.SetMaxCacheBytes(int(req.MaxCacheBytes))
	if a.httpFetcher != nil {
		a.httpFetcher.SetDefaultTimeout(time.Duration(req.RequestTimeout))
	}
	if req.ExecutionTimeout > 0 {
		a.executionTimeout.Store(int64(req.ExecutionTimeout))
	}
	if req.WorkflowGracePeriod != 0 {
		a.gracePeriod.Store(int64(req.WorkflowGracePeriod))
	}

	// The injected endpoint replaces the startup default (which only the fake and
	// test wirings set).
	a.mu.Lock()
	a.storageServiceURL = req.StorageServiceURL
	a.storageServiceTLS = req.StorageServiceTLS
	url, tls := a.storageServiceURL, a.storageServiceTLS
	a.mu.Unlock()

	fetcher, pub, err := a.storageFactory(url, tls, req.StorageKey, req.MaxBinarySize, time.Duration(req.BinaryFetchTimeout), a.logger)
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

	a.mu.Lock()
	if a.dispatcher == nil && a.dispatcherFactory != nil {
		d, err := a.dispatcherFactory(req.GatewayURL, time.Duration(req.GatewayRequestTimeout))
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("building remote dispatcher: %w", err)
		}
		if a.haveConfig {
			// Config may have arrived before credentials; apply it now so the
			// freshly built dispatcher has the vault's MasterPublicKey/T.
			d.SetConfig(a.lastConfig)
		}
		a.dispatcher = d
		a.logger.Infof("[app] remote dispatch enabled (gateway=%s)", req.GatewayURL)
	}
	a.mu.Unlock()
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

// NewConfidentialWorkflowsApp requires every production transport explicitly.
func NewConfidentialWorkflowsApp(tpe sdkpb.TeeType, lggr logger.Logger, config Config) (types.EnclaveApp, error) {
	if config.HTTPFetcher == nil {
		return nil, errors.New("HTTP fetcher is required")
	}
	if config.StorageFetcherFactory == nil {
		return nil, errors.New("storage fetcher factory is required")
	}
	if config.RemoteDispatcherFactory == nil {
		return nil, errors.New("remote dispatcher factory is required")
	}

	a := &confidentialWorkflowsApp{
		logger:            lggr,
		fetcher:           NewBinaryFetcher(lggr),
		httpFetcher:       config.HTTPFetcher,
		tpe:               tpe,
		limiter:           newExecutionLimiter(config.MaxConcurrentExecutions),
		storageFactory:    config.StorageFetcherFactory,
		dispatcherFactory: config.RemoteDispatcherFactory,
	}
	a.gracePeriod.Store(int64(types.DefaultWorkflowGracePeriod))
	a.requirementsHandler.Tee = a.validTee
	return a, nil
}

// NewTestConfidentialWorkflowsApp supplies direct clients for tests and fake environments.
func NewTestConfidentialWorkflowsApp(tpe sdkpb.TeeType, lggr logger.Logger, opts ...Option) types.EnclaveApp {
	a := &confidentialWorkflowsApp{
		logger:      lggr,
		fetcher:     NewBinaryFetcher(lggr),
		httpFetcher: httpfetch.NewFetcher(httpfetch.DefaultPolicy()),
		tpe:         tpe,
		limiter:     newExecutionLimiter(0),
		storageFactory: storageFetcherFactory(func() types.HTTPClient {
			return util.NewRestrictedHTTPClient()
		}),
	}
	a.gracePeriod.Store(int64(types.DefaultWorkflowGracePeriod))
	a.requirementsHandler.Tee = a.validTee
	for _, opt := range opts {
		opt(a)
	}
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

	// Hold every validated execution for the grace period before starting it.
	// The execution slot is already taken at this point, so the wait costs
	// throughput as well as latency.
	if grace := time.Duration(a.gracePeriod.Load()); grace > 0 {
		time.Sleep(grace)
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

	var helper host.ExecutionHelper = &enclaveExecutionHelper{
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

	helper = host.NewRestrictedExecutionHelper(helper, execution.Restrictions)

	// Execute the WASM binary with the deserialized ExecuteRequest.
	// The fetched binary is brotli-compressed.
	// chainlink-common's WASM host applies workflow-scoped resource limits (e.g.
	// concurrent capability calls) keyed off CRE metadata in the context.
	execCtx := contexts.WithCRE(context.Background(), contexts.CRE{
		Org:      execution.GetOrgId(),
		Owner:    execution.GetOwner(),
		Workflow: execution.WorkflowId,
	})
	// Both bounds come from the same setting: the ctx deadline unblocks host-side
	// capability and secrets calls, while the module timeout is what actually
	// interrupts the guest.
	execTimeout := time.Duration(a.executionTimeout.Load())
	if execTimeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(execCtx, execTimeout)
		defer cancel()
	}
	result, err := executeWasm(execCtx, a.logger, binary, execution.SdkExecuteRequest, true, helper, execTimeout)
	if err != nil {
		// A timed-out execution is a caller-facing condition, not an enclave
		// failure: the WASM host normalizes its epoch deadline to
		// context.DeadlineExceeded. Set the sentinel so the executor classifies
		// it as a user error (workflow ran over budget) instead of infrastructure.
		code := http.StatusInternalServerError
		errMsg := fmt.Sprintf("executing wasm: %s", err.Error())
		if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
			errMsg = fmt.Sprintf("%s: %s", types.ErrWasmExecutionTimeout, errMsg)
		}
		return nil, &types.ExecuteError{
			Error: errMsg,
			Code:  code,
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
