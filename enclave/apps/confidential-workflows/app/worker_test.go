package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	clconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/wasmruntime"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type localWorker struct{ app *confidentialWorkflowsApp }

func testCompiler(t *testing.T) *wasmruntime.Compiler {
	t.Helper()
	c, err := wasmruntime.NewCompiler(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

func (w localWorker) Run(_ context.Context, job worker.Job) (worker.Reply, error) {
	var execution confworkflowtypes.WorkflowExecution
	if err := proto.Unmarshal(job.Execution, &execution); err != nil {
		return worker.Reply{}, err
	}
	w.app.mu.Lock()
	dispatcher := w.app.dispatcher
	w.app.mu.Unlock()
	events := server.NewResponseEmitter()
	result, execErr := ExecuteWorkflow(w.app.logger, job.Limits, job.HTTPActionLimits, job.RequestID, &execution, job.ArtifactPath,
		job.SignedRequests, events, dispatcher, w.app.httpFetcher, job.ExecutionDeadline)
	return worker.Reply{Result: result, Error: execErr, Events: events.GetMetricEvents()}, nil
}

type capturingWorker struct {
	jobs   []worker.Job
	err    error
	result []byte
}

func (w *capturingWorker) Run(_ context.Context, job worker.Job) (worker.Reply, error) {
	w.jobs = append(w.jobs, job)
	result, _ := proto.Marshal(&confworkflowtypes.ConfidentialWorkflowResponse{SdkExecutionResult: &sdkpb.ExecutionResult{
		Result: &sdkpb.ExecutionResult_Value{Value: values.Proto(values.NewString("done"))}}})
	if w.result != nil {
		result = w.result
	}
	return worker.Reply{Result: result,
		Events: []types.MetricEvent{
			{Event: "capability_execution", Details: map[string]any{"duration_seconds": 0.123}},
			{Event: "capability_execution", Details: map[string]any{"duration_seconds": 0.456}},
		}}, w.err
}

func TestWorkerSnapshotsEffectiveState(t *testing.T) {
	w := &capturingWorker{}
	binary := []byte("verified artifact")
	a, locator := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) {
		s.WorkflowGracePeriod = -1
		s.RequestTimeout = Duration(2 * time.Second)
		s.ExecutionTimeout = Duration(time.Second)
		s.GatewayRequestTimeout = Duration(3 * time.Second)
		s.CRESettings = json.RawMessage(`{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"256mb","ExecutionResponseLimit":"13kb","CapabilityConcurrencyLimit":"7","LogLineLimit":"2kb","HTTPAction":{"CallLimit":"3","ConnectionTimeout":"1s","RequestSizeLimit":"4kb","ResponseSizeLimit":"5kb"}}}}}`)
	}, func(a *confidentialWorkflowsApp) { a.worker = w }, WithRemoteDispatcherFactory(func(GatewayConfig) (RemoteDispatcher, error) { return &testRemoteDispatcher{}, nil }))
	app := a.(*confidentialWorkflowsApp)
	var compiledBinary []byte
	app.compiler = compilerFunc(func(_ context.Context, _ logger.Logger, _ wasmlimits.Config, binary []byte, timeout time.Duration) (wasmruntime.PreparedArtifact, error) {
		compiledBinary = append([]byte(nil), binary...)
		path := filepath.Join(t.TempDir(), "artifact")
		require.NoError(t, os.WriteFile(path, []byte("native"), 0600))
		return wasmruntime.PreparedArtifact{Path: path, Deadline: time.Now().Add(timeout)}, nil
	})
	config := types.EnclaveConfig{Signers: [][]byte{{1}}, MasterPublicKey: []byte{2}, T: 1, F: 1}
	app.OnConfigUpdate(config)
	hash := sha256.Sum256(binary)
	execution := makeExecution(t, "workflow", locator, hash[:])
	execution.Owner, execution.ExecutionId, execution.OrgId = "owner", "execution", "org"
	input, err := proto.Marshal(execution)
	require.NoError(t, err)
	id := [32]byte{7}
	signed := []types.SignedComputeRequest{{ComputeRequest: types.ComputeRequest{RequestID: id}, Signature: []byte{8}}}
	emitter := server.NewResponseEmitter()
	_, execErr := a.Execute(id, types.AppIDConfidentialWorkflows, input, binary, nil, emitter, signed...)
	require.Nil(t, execErr)
	require.Len(t, w.jobs, 1)
	first := w.jobs[0]
	require.Equal(t, input, first.Execution)
	require.Equal(t, signed, first.SignedRequests)
	require.Equal(t, binary, compiledBinary)
	require.NotEmpty(t, first.ArtifactPath)
	_, statErr := os.Stat(first.ArtifactPath)
	require.ErrorIs(t, statErr, os.ErrNotExist, "parent removes artifact after Run")
	require.Equal(t, config, first.Config)
	require.Equal(t, 2*time.Second, first.HTTPTimeout)
	require.WithinDuration(t, time.Now().Add(time.Second), first.ExecutionDeadline, 100*time.Millisecond)
	require.Equal(t, 3*time.Second, first.Gateway.RequestTimeout)
	require.Equal(t, 256*clconfig.MByte, first.Limits.Memory)
	require.Equal(t, 13*clconfig.KByte, first.Limits.MaxResponseSize)
	require.Equal(t, 7, first.Limits.PendingCalls)
	require.Equal(t, uint32(2*clconfig.KByte), first.Limits.MaxLogLenBytes)
	wantHTTP := worker.HTTPActionLimits{CallLimit: 3, Fetch: httpfetch.Limits{
		ConnectionTimeout: time.Second, RequestSizeLimit: 4 * clconfig.KByte, ResponseSizeLimit: 5 * clconfig.KByte,
	}}
	require.Equal(t, wantHTTP, first.HTTPActionLimits)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	var decoded worker.Job
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, first.Gateway, decoded.Gateway)
	require.Equal(t, first.Limits, decoded.Limits)
	require.Equal(t, first.HTTPActionLimits, decoded.HTTPActionLimits)
	events := emitter.GetMetricEvents()
	require.Len(t, events, 3)
	require.Equal(t, 0.12, events[1].Details["duration_seconds"])
	require.Equal(t, 0.46, events[2].Details["duration_seconds"])

	config.Signers[0][0] = 9
	app.OnConfigUpdate(config)
	settings := testSettings()
	settings.RequestTimeout = Duration(4 * time.Second)
	settings.GatewayURL = "http://new-gateway.invalid"
	settings.GatewayRequestTimeout = Duration(9 * time.Second)
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, app.InjectSettings(raw))
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, binary, nil, emitter)
	require.Nil(t, execErr)
	require.Equal(t, byte(1), first.Config.Signers[0][0], "in-flight state must not change")
	require.Equal(t, byte(9), w.jobs[1].Config.Signers[0][0])
	require.Equal(t, 4*time.Second, w.jobs[1].HTTPTimeout)
	require.WithinDuration(t, time.Now().Add(time.Second), w.jobs[1].ExecutionDeadline, 100*time.Millisecond, "zero injection does not reset the timeout")
	require.Equal(t, first.Gateway, w.jobs[1].Gateway, "dispatcher settings are sticky after construction")
	require.Equal(t, resolveWASMLimits(workflowContext(execution), nil, nil), w.jobs[1].Limits, "omitted CRE settings restore defaults for the next worker")
	require.Equal(t, 256*clconfig.MByte, first.Limits.Memory, "in-flight limits must not change")
	defaultHTTP := newHTTPActionLimits(workflowContext(execution), nil, nil)
	require.Equal(t, worker.HTTPActionLimits{CallLimit: defaultHTTP.callLimit, Fetch: defaultHTTP.fetch}, w.jobs[1].HTTPActionLimits)
	require.Equal(t, wantHTTP, first.HTTPActionLimits, "in-flight HTTP limits must not change")

	w.err = errors.New("native fault")
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, binary, nil, emitter)
	require.Equal(t, "workflow worker failed", execErr.Error)
	require.NotContains(t, execErr.Error, types.ErrWasmExecutionTimeout)
	w.err, w.result = nil, []byte("bad protobuf")
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, binary, nil, emitter)
	require.Equal(t, "invalid worker result", execErr.Error)
	for _, job := range w.jobs {
		_, err := os.Stat(job.ArtifactPath)
		require.ErrorIs(t, err, os.ErrNotExist, "parent cleanup must cover worker and protocol failures")
	}
	for _, encoded := range [][]byte{{}, {0x0a, 0x00}} {
		w.result = encoded
		output, execErr := a.Execute(id, types.AppIDConfidentialWorkflows, input, binary, nil, emitter)
		require.Nil(t, execErr)
		require.Equal(t, encoded, output, "nil and empty SDK results must retain their distinct encodings")
	}
}

func TestRejectUntrustedWorkflowBinary(t *testing.T) {
	binary := []byte("verified artifact")
	hash := sha256.Sum256(binary)
	for _, tc := range []struct {
		name    string
		binary  []byte
		message string
	}{
		{"missing", nil, "no workflow binary supplied by the host"},
		{"tampered", []byte("tampered artifact"), "host-supplied binary hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &capturingWorker{}
			a, locator := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) {
				s.WorkflowGracePeriod = -1
			}, func(a *confidentialWorkflowsApp) { a.worker = w })
			input, err := proto.Marshal(makeExecution(t, "workflow", locator, hash[:]))
			require.NoError(t, err)
			_, execErr := a.Execute([32]byte{}, types.AppIDConfidentialWorkflows, input, tc.binary, nil, server.NewResponseEmitter())
			require.NotNil(t, execErr)
			require.Equal(t, 502, execErr.Code)
			require.Contains(t, execErr.Error, tc.message)
			require.Empty(t, w.jobs)
		})
	}
}

type compilerFunc func(context.Context, logger.Logger, wasmlimits.Config, []byte, time.Duration) (wasmruntime.PreparedArtifact, error)

func (f compilerFunc) Compile(ctx context.Context, lggr logger.Logger, limits wasmlimits.Config, binary []byte, timeout time.Duration) (wasmruntime.PreparedArtifact, error) {
	return f(ctx, lggr, limits, binary, timeout)
}

func TestCompilationFailureDoesNotLaunchWorker(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, errors.New("compiler failure")} {
		t.Run(cause.Error(), func(t *testing.T) {
			binary := []byte("source")
			hash := sha256.Sum256(binary)
			w := &capturingWorker{}
			a, locator := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) { s.WorkflowGracePeriod = -1 },
				func(a *confidentialWorkflowsApp) {
					a.worker = w
					a.compiler = compilerFunc(func(context.Context, logger.Logger, wasmlimits.Config, []byte, time.Duration) (wasmruntime.PreparedArtifact, error) {
						return wasmruntime.PreparedArtifact{}, cause
					})
				})
			input, err := proto.Marshal(makeExecution(t, "workflow", locator, hash[:]))
			require.NoError(t, err)
			_, execErr := a.Execute([32]byte{}, types.AppIDConfidentialWorkflows, input, binary, nil, server.NewResponseEmitter())
			require.NotNil(t, execErr)
			require.Empty(t, w.jobs)
			require.Contains(t, execErr.Error, cause.Error())
			if errors.Is(cause, context.DeadlineExceeded) {
				require.Equal(t, 504, execErr.Code)
				require.Contains(t, execErr.Error, types.ErrWasmExecutionTimeout)
			} else {
				require.Equal(t, 500, execErr.Code)
			}
		})
	}
}
