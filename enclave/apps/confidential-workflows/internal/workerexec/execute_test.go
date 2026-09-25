package workerexec

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bytecodealliance/wasmtime-go/v47"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/fake"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func build(t *testing.T, dir, target, name string, extraEnv ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-p", "1", "-o", out, target)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	data, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", data)
	return out
}

func jobFor(t *testing.T, name string) worker.Job {
	t.Helper()
	path := build(t, "../../app/testdata/"+name, ".", name+".wasm", "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return jobFromWasm(t, raw)
}

func jobFromWasm(t *testing.T, raw []byte) worker.Job {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	hash := sha256.Sum256(buf.Bytes())
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execution := &confworkflowtypes.WorkflowExecution{WorkflowId: "test", BinaryHash: hash[:],
		SdkExecuteRequest: &sdkpb.ExecuteRequest{Config: []byte("http://127.0.0.1:1"), Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: payload}}}}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)
	return worker.Job{RequestID: [32]byte{1}, Binary: buf.Bytes(), Execution: data, Limits: defaultLimits()}
}

func defaultLimits() wasmlimits.Config {
	c := cresettings.Default.PerWorkflow
	return wasmlimits.Config{
		Memory:                     c.WASMMemoryLimit.DefaultValue,
		MaxCompressedBinary:        c.WASMCompressedBinarySizeLimit.DefaultValue,
		MaxDecompressedBinary:      c.WASMBinarySizeLimit.DefaultValue,
		MaxResponseSize:            c.ExecutionResponseLimit.DefaultValue,
		PendingCalls:               c.CapabilityConcurrencyLimit.DefaultValue,
		EnableUserMetrics:          c.UserMetricEnabled.DefaultValue,
		MaxUserMetricPayload:       c.UserMetricPayloadLimit.DefaultValue,
		MaxUserMetricNameLength:    c.UserMetricNameLengthLimit.DefaultValue,
		MaxUserMetricLabels:        c.UserMetricLabelsPerMetric.DefaultValue,
		MaxUserMetricLabelValueLen: c.UserMetricLabelValueLength.DefaultValue,
		MaxSubscriptions:           cresettings.Default.WASMPollOneoffSubscriptionLimit.DefaultValue,
		MaxLogLenBytes:             uint32(c.LogLineLimit.DefaultValue),
	}
}

func TestNilSDKResult(t *testing.T) {
	raw, err := wasmtime.Wat2Wasm(`(module
		(import "env" "version_v2" (func))
		(memory (export "memory") 1)
		(func (export "_start")))`)
	require.NoError(t, err)
	path := build(t, "../..", "./environments/nitro-worker", "worker", "CGO_ENABLED=1")
	p, err := worker.NewProcesses(path, nil, []string{"HOME=" + t.TempDir()}, nil, logger.Test(t))
	require.NoError(t, err)
	reply, err := p.Run(t.Context(), jobFromWasm(t, raw))
	require.NoError(t, err)
	require.Nil(t, reply.Error)
	require.NotNil(t, reply.Result)
	require.Empty(t, reply.Result, "the baseline response has no SDK result field")
}

func TestRealWorkerBinary(t *testing.T) {
	workerPath := build(t, "../..", "./environments/nitro-worker", "worker", "CGO_ENABLED=1")
	p, err := worker.NewProcesses(workerPath, nil, []string{"HOME=" + t.TempDir(), "GOMAXPROCS=1"}, nil, logger.Test(t))
	require.NoError(t, err)
	hello := jobFor(t, "hello")
	start := time.Now()
	reply, err := p.Run(t.Context(), hello)
	require.NoError(t, err)
	require.Nil(t, reply.Error)
	var result confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(reply.Result, &result))
	require.Equal(t, "hello from enclave wasm", result.GetSdkExecutionResult().GetValue().GetStringValue())
	t.Logf("cold worker: %s", time.Since(start))
	start = time.Now()
	_, err = p.Run(t.Context(), hello)
	require.NoError(t, err)
	t.Logf("warm worker: %s", time.Since(start))

	spin := jobFor(t, "spin")
	spin.ExecutionTimeout = 100 * time.Millisecond
	reply, err = p.Run(t.Context(), spin)
	require.NoError(t, err)
	require.NotNil(t, reply.Error)
	require.Contains(t, reply.Error.Error, types.ErrWasmExecutionTimeout)
	reply, err = p.Run(t.Context(), spin)
	require.NoError(t, err)
	require.NotNil(t, reply.Error)
	require.Contains(t, reply.Error.Error, types.ErrWasmExecutionTimeout, "warm pure-compute executions must also time out")
	_, err = p.Run(t.Context(), hello)
	require.NoError(t, err, "a timeout must not affect later executions")

	t.Run("native crash", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("procfs identifies workers for fault injection")
		}
		spin.ExecutionTimeout = 5 * time.Second
		crashed := make(chan error, 1)
		go func() { _, err := p.Run(t.Context(), spin); crashed <- err }()
		require.Eventually(t, func() bool { return len(workerPIDs(t, workerPath)) == 1 }, 5*time.Second, time.Millisecond)
		pid := workerPIDs(t, workerPath)[0]
		completed := make(chan error, 1)
		go func() {
			_, err := p.Run(t.Context(), hello)
			completed <- err
		}()
		require.Eventually(t, func() bool { return len(workerPIDs(t, workerPath)) == 2 }, 5*time.Second, time.Millisecond)
		require.NoError(t, syscall.Kill(pid, syscall.SIGABRT))
		require.Error(t, <-crashed)
		require.NoError(t, <-completed, "a native worker failure must not affect a concurrent workflow")
		_, err = p.Run(t.Context(), hello)
		require.NoError(t, err, "capacity must be released after a worker crash")
		require.Empty(t, workerPIDs(t, workerPath))
	})

	httpJob := jobFor(t, "http-call")
	reply, err = p.Run(t.Context(), httpJob)
	require.NoError(t, err)
	require.Nil(t, reply.Error)
	var sawHTTP bool
	for _, e := range reply.Events {
		if e.Event == "capability_started" {
			sawHTTP = true
		}
	}
	require.True(t, sawHTTP, "helper events must cross the process boundary")
	require.NoError(t, proto.Unmarshal(reply.Result, &result))
	encoded, err := json.Marshal(&result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "400", "workflow HTTP restrictions must still apply")

	// A deferred provisioning failure does not reject a workflow without secrets.
	hello.Gateway.URL = "https://gateway.example"
	hello.KeyError = "key unavailable"
	reply = Execute(hello, logger.Test(t), &fake.FakeAttestor{}, httpfetch.NewFetcher(httpfetch.DefaultPolicy()))
	require.Nil(t, reply.Error)
	hello.Execution = []byte("bad protobuf")
	reply = Execute(hello, logger.Test(t), nil, nil)
	require.NotNil(t, reply.Error)
}

func workerPIDs(t *testing.T, executable string) []int {
	t.Helper()
	files, err := filepath.Glob("/proc/self/task/*/children")
	require.NoError(t, err)
	var pids []int
	for _, file := range files {
		data, _ := os.ReadFile(file)
		for _, id := range strings.Fields(string(data)) {
			path, _ := os.Readlink("/proc/" + id + "/exe")
			if path == executable {
				pid, err := strconv.Atoi(id)
				require.NoError(t, err)
				pids = append(pids, pid)
			}
		}
	}
	return pids
}
