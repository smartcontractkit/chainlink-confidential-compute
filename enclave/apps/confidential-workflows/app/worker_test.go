package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
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

func (w localWorker) Run(_ context.Context, job worker.Job) (worker.Reply, error) {
	var execution confworkflowtypes.WorkflowExecution
	if err := proto.Unmarshal(job.Execution, &execution); err != nil {
		return worker.Reply{}, err
	}
	w.app.mu.Lock()
	dispatcher := w.app.dispatcher
	w.app.mu.Unlock()
	var events worker.Events
	result, execErr := ExecuteWorkflow(wasmruntime.Execute, w.app.logger, job.RequestID, &execution, job.Binary,
		job.SignedRequests, &events, dispatcher, w.app.httpFetcher, job.ExecutionTimeout)
	reply := worker.Reply{Version: worker.Version, RequestID: job.RequestID, Outcome: worker.ExecutionError, Error: execErr}
	var err error
	reply.Events, err = events.Snapshot()
	if err == nil && execErr == nil {
		reply.Outcome = worker.Success
		reply.Result, err = proto.Marshal(result)
	}
	return reply, err
}

type capturingWorker struct {
	jobs []worker.Job
	err  error
}

func (w *capturingWorker) Run(_ context.Context, job worker.Job) (worker.Reply, error) {
	w.jobs = append(w.jobs, job)
	result, _ := proto.Marshal(&sdkpb.ExecutionResult{Result: &sdkpb.ExecutionResult_Value{Value: values.Proto(values.NewString("done"))}})
	return worker.Reply{Version: worker.Version, RequestID: job.RequestID, Outcome: worker.Success, Result: result,
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
	}, func(a *confidentialWorkflowsApp) { a.worker = w }, WithRemoteDispatcherFactory(func(GatewayConfig) (RemoteDispatcher, error) { return &testRemoteDispatcher{}, nil }))
	app := a.(*confidentialWorkflowsApp)
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
	_, execErr := a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter, signed...)
	require.Nil(t, execErr)
	require.Len(t, w.jobs, 1)
	first := w.jobs[0]
	require.Equal(t, input, first.Execution)
	require.Equal(t, signed, first.SignedRequests)
	require.Equal(t, binary, first.Binary)
	require.Equal(t, config, first.Config)
	require.Equal(t, 2*time.Second, first.HTTPTimeout)
	require.Equal(t, time.Second, first.ExecutionTimeout)
	require.Equal(t, 3*time.Second, first.Gateway.RequestTimeout)
	events := emitter.GetMetricEvents()
	require.Len(t, events, 3)
	require.Equal(t, 0.12, events[1].Details["duration_seconds"])
	require.Equal(t, 0.46, events[2].Details["duration_seconds"])

	config.Signers[0][0] = 9
	app.OnConfigUpdate(config)
	settings := testSettings(app.storageServiceURL)
	settings.RequestTimeout = Duration(4 * time.Second)
	settings.GatewayURL = "http://new-gateway.invalid"
	settings.GatewayRequestTimeout = Duration(9 * time.Second)
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, app.InjectSettings(raw))
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter)
	require.Nil(t, execErr)
	require.Equal(t, byte(1), first.Config.Signers[0][0], "in-flight state must not change")
	require.Equal(t, byte(9), w.jobs[1].Config.Signers[0][0])
	require.Equal(t, 4*time.Second, w.jobs[1].HTTPTimeout)
	require.Equal(t, time.Second, w.jobs[1].ExecutionTimeout, "zero injection does not reset the timeout")
	require.Equal(t, first.Gateway, w.jobs[1].Gateway, "dispatcher settings are sticky after construction")

	w.err = errors.New("native fault")
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter)
	require.Equal(t, "workflow worker failed", execErr.Error)
	require.NotContains(t, execErr.Error, types.ErrWasmExecutionTimeout)
}
