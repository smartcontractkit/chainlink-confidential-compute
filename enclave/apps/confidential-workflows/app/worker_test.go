package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	clconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
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
	events := server.NewResponseEmitter()
	result, execErr := ExecuteWorkflow(wasmruntime.Execute, w.app.logger, job.Limits, job.RequestID, &execution, job.Binary,
		job.SignedRequests, events, dispatcher, w.app.httpFetcher, job.ExecutionTimeout)
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
		s.CRESettings = json.RawMessage(`{"workflow":{"workflow":{"PerWorkflow":{"WASMMemoryLimit":"256mb","ExecutionResponseLimit":"13kb","CapabilityConcurrencyLimit":"7","LogLineLimit":"2kb"}}}}`)
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
	require.Equal(t, 256*clconfig.MByte, first.Limits.Memory)
	require.Equal(t, 13*clconfig.KByte, first.Limits.MaxResponseSize)
	require.Equal(t, 7, first.Limits.PendingCalls)
	require.Equal(t, uint32(2*clconfig.KByte), first.Limits.MaxLogLenBytes)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	var decoded worker.Job
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, first.Limits, decoded.Limits)
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
	require.Equal(t, resolveWASMLimits(workflowContext(execution), nil, nil), w.jobs[1].Limits, "omitted CRE settings restore defaults for the next worker")
	require.Equal(t, 256*clconfig.MByte, first.Limits.Memory, "in-flight limits must not change")

	w.err = errors.New("native fault")
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter)
	require.Equal(t, "workflow worker failed", execErr.Error)
	require.NotContains(t, execErr.Error, types.ErrWasmExecutionTimeout)
	w.err, w.result = nil, []byte("bad protobuf")
	_, execErr = a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter)
	require.Equal(t, "invalid worker result", execErr.Error)
	for _, encoded := range [][]byte{{}, {0x0a, 0x00}} {
		w.result = encoded
		output, execErr := a.Execute(id, types.AppIDConfidentialWorkflows, input, nil, emitter)
		require.Nil(t, execErr)
		require.Equal(t, encoded, output, "nil and empty SDK results must retain their distinct encodings")
	}
}
