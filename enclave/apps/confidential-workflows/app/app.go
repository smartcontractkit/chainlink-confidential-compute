package app

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/wasmruntime"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
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
	httpFetcher         *httpfetch.Fetcher
	requirementsHandler host.RequirementsHandler
	tpe                 sdkpb.TeeType
	worker              WorkerRunner
	compiler            workflowCompiler
	gatewayTimeout      time.Duration

	// limiter reduces memory pressure from concurrent executions; it is not an
	// RSS limit. Unbounded unless WithMaxConcurrentExecutions
	// is set (the nitro entrypoint derives a limit from enclave memory).
	limiter *executionLimiter

	// executionTimeout bounds preparation plus execution (nanoseconds; 0 = the WASM
	// host's own default). Injected via InjectSettings, read on every Execute,
	// so it is atomic rather than guarded by mu.
	executionTimeout atomic.Int64

	// gracePeriod is how long a validated execution waits before it starts
	// running (nanoseconds; non-positive = no wait). Same reasoning as above for
	// the atomic.
	gracePeriod     atomic.Int64
	limiterSettings *mutableSettings

	// Runtime config + secrets injected via InjectSettings (host over vsock). A
	// Nitro EIF is measured (PCR), so environment-specific endpoints can't be
	// baked in; the storage endpoint, the ed25519 storage key, and the gateway
	// URL all arrive at runtime. mu guards everything below.
	mu                sync.Mutex
	dispatcher        RemoteDispatcher        // nil = local mode
	dispatcherFactory RemoteDispatcherFactory // builds dispatcher on first GatewayURL injection
	lastConfig        types.EnclaveConfig
	haveConfig        bool
	gatewayConfig     GatewayConfig
}

var _ types.EnclaveApp = (*confidentialWorkflowsApp)(nil)

// Config requires explicit transports to prevent direct network access.
type Config struct {
	Compiler                *wasmruntime.Compiler
	Worker                  WorkerRunner
	GatewayTimeout          time.Duration
	HTTPFetcher             *httpfetch.Fetcher
	RemoteDispatcherFactory RemoteDispatcherFactory
	MaxConcurrentExecutions int64
}

type WorkerRunner interface {
	Run(context.Context, worker.Job) (worker.Reply, error)
}

type workflowCompiler interface {
	Compile(context.Context, logger.Logger, wasmlimits.Config, []byte, time.Duration) (wasmruntime.PreparedArtifact, error)
}

type Option func(*confidentialWorkflowsApp)

type GatewayConfig = worker.GatewayConfig

// RemoteDispatcherFactory defers construction until the host injects the gateway URL.
type RemoteDispatcherFactory func(gateway GatewayConfig) (RemoteDispatcher, error)

// WithRemoteDispatcher supplies a dispatcher to in-process test workers only.
// Process-backed workers construct their own from the gateway configuration
// captured by the dispatcher factory during settings injection.
func WithRemoteDispatcher(d RemoteDispatcher) Option {
	return func(a *confidentialWorkflowsApp) {
		a.dispatcher = d
	}
}

// WithRemoteDispatcherFactory supplies a builder that constructs the remote
// dispatcher from a Gateway URL and client timeout injected at runtime (via
// InjectSettings). The measured EIF can't bake the gateway URL, so the
// nitro/fake mains pass a factory here and the dispatcher is created when the
// host injects the URL. InjectSettings resolves the request timeout first.
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

// WithMaxConcurrentExecutions bounds concurrent Execute calls to n; n <= 0 means
// unbounded. The nitro entrypoint derives n from enclave memory as an admission
// heuristic. Fake/local runs and tests leave it unbounded.
func WithMaxConcurrentExecutions(n int64) Option {
	return func(a *confidentialWorkflowsApp) {
		a.limiter = newExecutionLimiter(n)
	}
}

// InjectSettings receives the settings JSON injected by the host over vsock and
// wires up what it carries: on the first injection, the remote dispatcher (via
// the factory). The required fields are asserted before anything is applied, so
// a deployment that forgot one fails the injection instead of running
// half-configured; see WorkflowSettings. The timeouts (global request, gateway
// client, workflow execution) fall back to the built-in defaults when omitted.
// Safe to call again (e.g. key rotation), as long as the payload stays complete.
// The storage fields are ignored here: the host fetches workflow binaries.
func (a *confidentialWorkflowsApp) InjectSettings(raw json.RawMessage) error {
	var req WorkflowSettings
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parsing settings: %w", err)
	}
	if err := req.validate(); err != nil {
		return err
	}
	var limiterSettings settings.Getter
	if len(req.CRESettings) > 0 {
		var err error
		// Use the Nop logger to avoid an empty-orgId error on every scoped
		// lookup. Execution logs report missing org IDs and setting fallbacks.
		// ref: https://github.com/smartcontractkit/chainlink/blob/2b6b3d42d648cf66c205006a0fb305373dd54f42/core/services/chainlink/application.go#L312
		limiterSettings, err = (settings.GetterConfig{}).NewJSONGetter(req.CRESettings)
		if err != nil {
			return fmt.Errorf("parsing CRE settings: %w", err)
		}
	}

	if a.httpFetcher != nil {
		a.httpFetcher.SetDefaultTimeout(time.Duration(req.RequestTimeout))
	}
	if req.ExecutionTimeout > 0 {
		a.executionTimeout.Store(int64(req.ExecutionTimeout))
	}
	if req.WorkflowGracePeriod != 0 {
		a.gracePeriod.Store(int64(req.WorkflowGracePeriod))
	}

	a.mu.Lock()
	if a.dispatcher == nil && a.dispatcherFactory != nil {
		gw := GatewayConfig{
			URL:            req.GatewayURL,
			RequestTimeout: time.Duration(req.GatewayRequestTimeout),
			RetryBackoff:   time.Duration(req.GatewayRetryBackoff),
			RetryTimeout:   time.Duration(req.GatewayRetryTimeout),
		}
		if gw.RequestTimeout <= 0 {
			gw.RequestTimeout = a.gatewayTimeout
		}
		d, err := a.dispatcherFactory(gw)
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
		a.gatewayConfig = gw
		a.logger.Infof("[app] remote dispatch enabled (gateway=%s)", req.GatewayURL)
	}
	a.mu.Unlock()
	a.limiterSettings.SetGetter(limiterSettings)
	return nil
}

// OnConfigUpdate propagates the enclave config to the remote dispatcher so it
// has the vault's MasterPublicKey and threshold for TDH2 decryption. It also
// stores the config so a dispatcher built later (credentials can arrive after
// config) picks it up in InjectSettings.
func (a *confidentialWorkflowsApp) OnConfigUpdate(config types.EnclaveConfig) {
	a.mu.Lock()
	a.lastConfig = config.Copy()
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
	if config.Compiler == nil {
		return nil, errors.New("compiler is required")
	}
	if config.Worker == nil {
		return nil, errors.New("worker runner is required")
	}
	if config.HTTPFetcher == nil {
		return nil, errors.New("HTTP fetcher is required")
	}
	if config.RemoteDispatcherFactory == nil {
		return nil, errors.New("remote dispatcher factory is required")
	}

	a := &confidentialWorkflowsApp{
		worker:            config.Worker,
		compiler:          config.Compiler,
		gatewayTimeout:    config.GatewayTimeout,
		logger:            lggr,
		httpFetcher:       config.HTTPFetcher,
		tpe:               tpe,
		limiter:           newExecutionLimiter(config.MaxConcurrentExecutions),
		limiterSettings:   &mutableSettings{},
		dispatcherFactory: config.RemoteDispatcherFactory,
	}
	a.gracePeriod.Store(int64(types.DefaultWorkflowGracePeriod))
	a.requirementsHandler.Tee = a.validTee
	return a, nil
}

// NewTestConfidentialWorkflowsApp supplies direct clients for tests and fake environments.
func NewTestConfidentialWorkflowsApp(tpe sdkpb.TeeType, lggr logger.Logger, opts ...Option) types.EnclaveApp {
	a := &confidentialWorkflowsApp{
		logger:          lggr,
		httpFetcher:     httpfetch.NewFetcher(httpfetch.DefaultPolicy()),
		tpe:             tpe,
		limiter:         newExecutionLimiter(0),
		limiterSettings: &mutableSettings{},
	}
	a.gracePeriod.Store(int64(types.DefaultWorkflowGracePeriod))
	a.requirementsHandler.Tee = a.validTee
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *confidentialWorkflowsApp) Execute(requestID [32]byte, appID string, inputData []byte, unauthenticatedData []byte, secretsMap map[string][]byte, emitter types.Emitter, rawSignedRequests ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
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

	// unauthenticatedData may carry the binary the host pre-fetched. It is not
	// covered by the DON signatures, so it is verified against the signed
	// binary_hash below like any other source.
	hostBinary := unauthenticatedData

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

	// The binary arrives as unauthenticatedData, fetched by the host. The host
	// is untrusted, so verify it against the signed binary_hash before
	// executing.
	if len(hostBinary) == 0 {
		return nil, &types.ExecuteError{
			Error: "no workflow binary supplied by the host",
			Code:  http.StatusBadGateway,
		}
	}
	if actual := sha256.Sum256(hostBinary); !bytes.Equal(actual[:], execution.BinaryHash) {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("host-supplied binary hash mismatch: expected %x, got %x", execution.BinaryHash, actual[:]),
			Code:  http.StatusBadGateway,
		}
	}
	binary := hostBinary

	if !host.CheckRequirements(context.Background(), a.requirementsHandler, execution.Requirements) {
		reqSerialized, _ := json.Marshal(execution.Requirements)
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("this TEE doesn't meet the requirements %s of the workflow: %s", reqSerialized, execution.WorkflowId),
			Code:  http.StatusBadRequest,
		}
	}

	execCtx := workflowContext(&execution)
	executionLogger := logger.With(a.logger, append(contexts.CREValue(execCtx).LoggerKVs(), "execution_id", execution.GetExecutionId())...)
	if execution.GetOrgId() == "" {
		executionLogger.Warnw("Workflow execution is missing org ID")
	}
	snapshot := a.limiterSettings.Snapshot()
	resolved := resolveWASMLimits(execCtx, executionLogger, snapshot)
	httpLimits := newHTTPActionLimits(execCtx, executionLogger, snapshot)
	a.mu.Lock()
	cfg, gw := a.lastConfig.Copy(), a.gatewayConfig
	a.mu.Unlock()
	httpTimeout := a.httpFetcher.DefaultTimeout()
	prepared, err := a.compiler.Compile(execCtx, executionLogger, resolved, binary, time.Duration(a.executionTimeout.Load()))
	if err != nil {
		return nil, wasmExecutionError(err)
	}
	defer wasmruntime.RemoveArtifact(executionLogger, prepared.Path)
	reply, runErr := a.worker.Run(context.Background(), worker.Job{
		Limits: resolved, HTTPActionLimits: worker.HTTPActionLimits{CallLimit: httpLimits.callLimit, Fetch: httpLimits.fetch},
		RequestID: requestID, Execution: inputData, ArtifactPath: prepared.Path,
		Config: cfg, Gateway: gw,
		HTTPTimeout: httpTimeout, ExecutionDeadline: prepared.Deadline, SignedRequests: rawSignedRequests,
	})
	if runErr != nil {
		a.logger.Errorw("workflow worker failed", "requestID", fmt.Sprintf("%x", requestID), "workflowID", execution.WorkflowId, "error", runErr)
		return nil, &types.ExecuteError{Error: "workflow worker failed", Code: http.StatusInternalServerError}
	}
	for _, event := range reply.Events {
		emitter.Emit(event.Event, event.Details)
	}
	if reply.Error != nil {
		return nil, reply.Error
	}
	var response confworkflowtypes.ConfidentialWorkflowResponse
	if err := proto.Unmarshal(reply.Result, &response); err != nil {
		return nil, &types.ExecuteError{Error: "invalid worker result", Code: http.StatusInternalServerError}
	}
	return reply.Result, nil
}

// ExecuteWorkflow reuses the same helper and timeout policy in workers and local tests.
func ExecuteWorkflow(lggr logger.Logger, resolved wasmlimits.Config, httpLimits worker.HTTPActionLimits, requestID [32]byte, execution *confworkflowtypes.WorkflowExecution, artifactPath string, signedRequests []types.SignedComputeRequest, emitter types.Emitter, dispatcher RemoteDispatcher, fetcher *httpfetch.Fetcher, deadline time.Time) ([]byte, *types.ExecuteError) {
	helper := host.NewRestrictedExecutionHelper(&enclaveExecutionHelper{
		requestID: requestID, workflowID: execution.WorkflowId, owner: execution.GetOwner(),
		executionID: execution.GetExecutionId(), orgID: execution.GetOrgId(), signedRequests: signedRequests,
		logger: lggr, emitter: emitter, remoteDispatcher: dispatcher, httpFetcher: fetcher,
		httpLimits: httpActionLimits{callLimit: httpLimits.CallLimit, fetch: httpLimits.Fetch},
	}, execution.Restrictions)

	execCtx := workflowContext(execution)
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithDeadline(execCtx, deadline)
		defer cancel()
	}
	executionLogger := logger.With(lggr, append(contexts.CREValue(execCtx).LoggerKVs(), "execution_id", execution.GetExecutionId())...)
	result, err := wasmruntime.Execute(execCtx, executionLogger, resolved, artifactPath, execution.SdkExecuteRequest, helper)
	if err != nil {
		return nil, wasmExecutionError(err)
	}

	// Wrapping here preserves a nil SDK result as a valid, empty response.
	response, err := proto.Marshal(&confworkflowtypes.ConfidentialWorkflowResponse{SdkExecutionResult: result})
	if err != nil {
		return nil, &types.ExecuteError{Error: fmt.Sprintf("marshalling workflow response: %s", err), Code: http.StatusInternalServerError}
	}
	return response, nil
}

func wasmExecutionError(err error) *types.ExecuteError {
	code := http.StatusInternalServerError
	message := fmt.Sprintf("executing wasm: %s", err)
	if errors.Is(err, context.DeadlineExceeded) {
		code = http.StatusGatewayTimeout
		message = fmt.Sprintf("%s: %s", types.ErrWasmExecutionTimeout, message)
	}
	return &types.ExecuteError{Error: message, Code: code}
}

func workflowContext(execution *confworkflowtypes.WorkflowExecution) context.Context {
	return contexts.WithCRE(context.Background(), contexts.CRE{
		Org: execution.GetOrgId(), Owner: execution.GetOwner(), Workflow: execution.WorkflowId,
	})
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
