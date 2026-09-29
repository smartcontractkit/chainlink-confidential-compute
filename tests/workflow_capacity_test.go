package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	enclaveclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	storagepb "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestConfidentialWorkflowsCapacityE2E exercises the real admission limiter,
// artifact transport, WASM runtime and attested responses without deploying DONs.
func TestConfidentialWorkflowsCapacityE2E(t *testing.T) {
	if UseFakeEnclave() || UseLegacyEnclaves() || os.Getenv("REMOTE_ENCLAVE_URL") != "" || os.Getenv("REMOTE_ENCLAVE_URLS") != "" {
		t.Skip("capacity test requires a locally provisioned current Nitro enclave")
	}
	require.False(t, vsock.IsFake(), "capacity test must use real VSOCK")
	root := findProjectRoot(t)
	binary := buildCapacityWorkflow(t, root)
	hash := sha256.Sum256(binary)

	// Holding downloads keeps admitted slots occupied independently of CPU speed.
	// Releasing them together also exercises concurrent Go-WASM compilation.
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	artifact := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		case <-r.Context().Done():
			return
		}
		select {
		case <-release:
			_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(binary))
		case <-r.Context().Done():
		}
	}))
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	artifact.Listener = listener
	artifact.Start()
	t.Cleanup(artifact.Close)
	artifactURL := fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)
	storageListener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	storageServer := grpc.NewServer()
	storagepb.RegisterNodeServiceServer(storageServer, &capacityStorageService{url: artifactURL})
	go func() { _ = storageServer.Serve(storageListener) }()
	t.Cleanup(storageServer.Stop)

	t.Setenv("OUTBOUND_ALLOW_LOCAL_FOR_TESTS", "true")
	t.Setenv("ENCLAVE_MEMORY_MIB", "2048")
	t.Setenv("TOTAL_MEMORY_MIB", "4096")
	t.Setenv("ENCLAVE_SETTINGS", fmt.Sprintf(
		`{"storageKey":%q,"storageServiceUrl":%q,"gatewayUrl":%q,"binaryFetchTimeout":"2m","executionTimeout":"2m","workflowGracePeriod":"-1s"}`,
		fmt.Sprintf("%064x", 1),
		fmt.Sprintf("127.0.0.1:%d", storageListener.Addr().(*net.TCPAddr).Port), artifactURL))
	local := testhelpers.SetupLocalEnclaves(t, testhelpers.LocalEnclaveSetupConfig{
		RepoRoot: root, AppName: "confidential-workflows", EnclaveCount: 1, HostIP: "127.0.0.1",
	})
	defer local.CleanupAll()
	node := local.Enclaves[0]

	// /memory reports guest RAM, not the larger nitro-cli allocation or host RAM.
	memoryTransport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return vsock.Dial(16, 5000, nil)
	}}
	defer memoryTransport.CloseIdleConnections()
	memoryClient := &http.Client{Transport: memoryTransport, Timeout: 5 * time.Second}
	resp, err := memoryClient.Get("http://enclave" + types.MemoryPath)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var memory types.MemoryEstimateResponse
	require.NoError(t, json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&memory))
	require.Positive(t, memory.TotalMB, "guest memory must be observable")
	minCapacity, maxCapacity := workflowCapacityBounds(memory.TotalMB)
	burst := 2 * maxCapacity
	require.LessOrEqual(t, burst, cap(entered), "unexpected capacity for the test enclave")
	t.Logf("guest RAM=%d MiB; reserve=%d MiB; per execution=%d MiB; capacity=%d..%d; burst=%d distinct workflows",
		memory.TotalMB, memlimit.ReserveMB, memlimit.PerExecMB, minCapacity, maxCapacity, burst)

	keys := mustGenerateEd25519Keys(t, 1)
	tdh2Keys := mustGenerateTDH2Keys(t, 1, 1)
	config, err := json.Marshal(types.EnclaveConfig{Signers: keys.PublicKeys, MasterPublicKey: tdh2Keys.MasterPublicKey, T: 1, F: 0})
	require.NoError(t, err)
	configNode := node
	configNode.EnclaveURL = local.ConfigURLs[0]
	httpClient := &http.Client{Timeout: 3 * time.Minute}
	_, err = util.SetNodeConfig(t.Context(), configNode, types.ConfigRequest{Config: config}, httpClient)
	require.NoError(t, err)
	pool, err := enclaveclient.NewPoolWithConfig(local.Enclaves, nil, httpClient, enclaveclient.PoolConfig{
		Cache: enclaveclient.DefaultCacheConfig, Session: enclaveclient.DefaultSessionConfig,
		RequestTimeoutResolverFn: func(context.Context, bool) (time.Duration, error) { return 3 * time.Minute, nil },
	})
	require.NoError(t, err)
	pubKeys, err := pool.GetPublicKeys(t.Context(), [32]byte{1}, nil)
	require.NoError(t, err)
	enclaveKeys := mustGetEnclavePublicKeys(t, pubKeys)
	require.Len(t, enclaveKeys, 1)

	execute := func(ctx context.Context, index int) error {
		id := sha256.Sum256([]byte(fmt.Sprintf("capacity-workflow-%d", index)))
		data, err := proto.Marshal(&confworkflowtypes.WorkflowExecution{
			WorkflowId: fmt.Sprintf("%x", id), ExecutionId: fmt.Sprintf("%x", id),
			BinaryUrl: "capacity-workflow", BinaryHash: hash[:],
			SdkExecuteRequest: &sdkpb.ExecuteRequest{Request: &sdkpb.ExecuteRequest_Trigger{
				Trigger: &sdkpb.Trigger{Id: 0, Payload: &anypb.Any{
					TypeUrl: "type.googleapis.com/capabilities.internal.basictrigger.v1.Outputs",
				}},
			}},
		})
		if err != nil {
			return err
		}
		req := types.ComputeRequest{
			RequestID: id, PublicData: data, MasterPublicKey: tdh2Keys.MasterPublicKey,
			EnclaveEphemeralPublicKey: enclaveKeys[0].EnclavePublicKey,
			AppID:                     types.AppIDConfidentialWorkflows, Version: "1.0.0",
		}
		digest := req.Hash()
		signature := ed25519.Sign(keys.PrivateKeys[0], types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), digest[:]))
		responses, err := pool.ExecuteBatch(ctx, []types.SignedComputeRequest{{ComputeRequest: req, Signature: signature}}, [][32]byte{node.EnclaveID})
		if err != nil {
			return err
		}
		if len(responses) != 1 {
			return fmt.Errorf("workflow %d: got %d responses, want 1", index, len(responses))
		}
		var result confworkflowtypes.ConfidentialWorkflowResponse
		if err := proto.Unmarshal(responses[0].Output, &result); err != nil {
			return err
		}
		if result.GetSdkExecutionResult().GetValue().GetStringValue() != "hello from enclave wasm" {
			return fmt.Errorf("workflow %d: unexpected WASM result: %v", index, &result)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	var wg sync.WaitGroup
	defer func() { unblock(); cancel(); wg.Wait() }()
	results := make(chan error, burst)
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- execute(ctx, i)
		}()
	}
	admitted, rejected := 0, 0
	admissionDeadline := time.NewTimer(30 * time.Second)
	defer admissionDeadline.Stop()
	for admitted+rejected < burst {
		select {
		case <-entered:
			admitted++
		case err := <-results:
			// The enclave server wraps app errors (including Code 429) in HTTP 500.
			require.ErrorContains(t, err, "enclave at capacity: too many concurrent executions",
				"only explicit capacity rejection is acceptable before release")
			rejected++
		case <-admissionDeadline.C:
			t.Fatalf("admission did not settle: admitted=%d rejected=%d burst=%d", admitted, rejected, burst)
		}
	}
	require.GreaterOrEqual(t, admitted, minCapacity)
	require.LessOrEqual(t, admitted, maxCapacity)
	require.Positive(t, rejected, "burst never exercised overload protection")
	t.Logf("admitted=%d rejected=%d; releasing downloads for concurrent WASM execution", admitted, rejected)
	unblock()
	for range admitted {
		select {
		case err := <-results:
			require.NoError(t, err, "admitted workflow must survive the burst and return its attested WASM result")
		case <-ctx.Done():
			t.Fatal("admitted workflows did not finish: ", ctx.Err())
		}
	}
	require.NoError(t, execute(ctx, burst), "fresh workflow must succeed after draining; slots must be released")
}

type capacityStorageService struct {
	storagepb.UnimplementedNodeServiceServer
	url string
}

func (s *capacityStorageService) DownloadArtifact(context.Context, *storagepb.DownloadArtifactRequest) (*storagepb.DownloadArtifactResponse, error) {
	return &storagepb.DownloadArtifactResponse{Url: s.url}, nil
}

func buildCapacityWorkflow(t *testing.T, root string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "hello.wasm")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-p", "1", "-o", out, "./hello")
	cmd.Dir = filepath.Join(root, "enclave/apps/confidential-workflows/app/testdata")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOMAXPROCS=1")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "build workflow: %s", output)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var compressed bytes.Buffer
	writer := brotli.NewWriter(&compressed)
	_, err = writer.Write(raw)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return compressed.Bytes()
}

// /memory rounds MiB whereas memlimit truncates; only a boundary can differ by one slot.
func workflowCapacityBounds(totalMB uint64) (int, int) {
	capacity := func(total uint64) int {
		if total <= memlimit.ReserveMB || memlimit.PerExecMB == 0 {
			return 1
		}
		return max(1, int((total-memlimit.ReserveMB)/memlimit.PerExecMB))
	}
	if totalMB == 0 {
		return 1, 1
	}
	return capacity(totalMB - 1), capacity(totalMB)
}

func TestWorkflowCapacityBounds(t *testing.T) {
	for _, tc := range []struct {
		total    uint64
		min, max int
	}{{0, 1, 1}, {512, 1, 1}, {1024, 1, 1}, {1152, 1, 1}, {1950, 7, 7}, {2048, 7, 8}, {2049, 8, 8}} {
		t.Run(fmt.Sprint(tc.total), func(t *testing.T) {
			minCapacity, maxCapacity := workflowCapacityBounds(tc.total)
			require.Equal(t, tc.min, minCapacity)
			require.Equal(t, tc.max, maxCapacity)
		})
	}
}
