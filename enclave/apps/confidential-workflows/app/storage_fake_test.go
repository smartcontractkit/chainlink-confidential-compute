package app

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// testStorageKeyHex is a deterministic ed25519 seed used to authenticate to the
// fake storage service in tests (the fake does not verify the JWT).
const testStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

// testLocator is the artifact id tests place in WorkflowExecution.BinaryUrl; the
// fake storage service ignores it and serves the configured binary.
const testLocator = "test-artifact-id"

// fakeStorage is a minimal in-process CRE storage service for tests: its
// DownloadArtifact returns a pre-signed URL that serves the raw binary bytes.
type fakeStorage struct {
	storage_service.UnimplementedNodeServiceServer
	url string
}

func (f *fakeStorage) DownloadArtifact(_ context.Context, _ *storage_service.DownloadArtifactRequest) (*storage_service.DownloadArtifactResponse, error) {
	return &storage_service.DownloadArtifactResponse{Url: f.url}, nil
}

// startFakeStorage serves rawBinary over HTTP and a gRPC NodeService that hands
// out that URL. Returns the gRPC dial address; teardown is via t.Cleanup.
func startFakeStorage(t *testing.T, rawBinary []byte) string {
	t.Helper()

	// The real storage service serves the artifact base64-encoded; the fetcher
	// decodes it, so the fake must serve base64 too.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(base64.StdEncoding.EncodeToString(rawBinary)))
	}))
	t.Cleanup(httpSrv.Close)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcSrv := grpc.NewServer()
	storage_service.RegisterNodeServiceServer(grpcSrv, &fakeStorage{url: httpSrv.URL})
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	return lis.Addr().String()
}

// newStorageBackedApp builds an app wired to a fake storage service serving
// rawBinary, with the test storage credentials injected. Returns the app and the
// locator to place in WorkflowExecution.BinaryUrl.
func newStorageBackedApp(t *testing.T, rawBinary []byte, opts ...Option) (types.EnclaveApp, string) {
	t.Helper()

	addr := startFakeStorage(t, rawBinary)
	allOpts := append([]Option{WithStorageService(addr, false)}, opts...)
	a := NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), nil, allOpts...)
	require.NoError(t, a.(*confidentialWorkflowsApp).InjectSettings(types.SettingsRequest{StorageKey: testStorageKeyHex}))
	return a, testLocator
}
