package app

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestArtifactID guards the locator -> storage-service id extraction. A full
// BinaryUrl must collapse to the bare artifact id; a value that is already an id
// must pass through unchanged. Passing the full URL as the id is what caused the
// storage service to return NotFound.
func TestArtifactID(t *testing.T) {
	const id = "00ff45641a2cb008d2cc7a8ad509671bf130b63e0dd3c1539dfa7dc61958b86d"

	tests := []struct {
		name    string
		locator string
		want    string
	}{
		{
			name:    "full url with artifacts segment",
			locator: "https://storage.cre.stage.external.griddle.sh/artifacts/" + id + "/binary.wasm",
			want:    id,
		},
		{
			name:    "url without binary filename",
			locator: "https://storage.example.com/artifacts/" + id,
			want:    id,
		},
		{
			name:    "url without artifacts segment falls back to parent dir",
			locator: "https://storage.example.com/" + id + "/binary.wasm",
			want:    id,
		},
		{
			name:    "bare id passes through",
			locator: id,
			want:    id,
		},
		{
			name:    "trailing slash tolerated",
			locator: "https://storage.example.com/artifacts/" + id + "/",
			want:    id,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, artifactID(tt.locator))
		})
	}
}

// recordingStorage is a fake NodeService that records the DownloadArtifactRequest
// it receives so tests can assert exactly what the enclave sent.
type recordingStorage struct {
	storage_service.UnimplementedNodeServiceServer
	url string

	mu      sync.Mutex
	lastReq *storage_service.DownloadArtifactRequest
}

func (r *recordingStorage) DownloadArtifact(_ context.Context, req *storage_service.DownloadArtifactRequest) (*storage_service.DownloadArtifactResponse, error) {
	r.mu.Lock()
	r.lastReq = req
	r.mu.Unlock()
	return &storage_service.DownloadArtifactResponse{Url: r.url}, nil
}

func (r *recordingStorage) request() *storage_service.DownloadArtifactRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastReq
}

// TestStorageFetcher_SendsBareArtifactID is the end-to-end regression guard: when
// FetchBinary is given a full BinaryUrl, the DownloadArtifactRequest that reaches
// the storage service must carry the bare artifact id and ARTIFACT_TYPE_BINARY,
// not the full URL.
func TestStorageFetcher_SendsBareArtifactID(t *testing.T) {
	const id = "00ff45641a2cb008d2cc7a8ad509671bf130b63e0dd3c1539dfa7dc61958b86d"
	locator := "https://storage.cre.stage.external.griddle.sh/artifacts/" + id + "/binary.wasm"
	rawBinary := []byte("wasm-bytes")

	httpSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(base64.StdEncoding.EncodeToString(rawBinary)))
	}))
	t.Cleanup(httpSrv.Close)

	fake := &recordingStorage{url: httpSrv.URL}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	storage_service.RegisterNodeServiceServer(grpcSrv, fake)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	f, _, err := NewStorageFetcher(lis.Addr().String(), false, testStorageKeyHex, 0, 5*time.Second, logger.Test(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	got, err := f.FetchBinary(context.Background(), locator)
	require.NoError(t, err)
	require.Equal(t, rawBinary, got)

	req := fake.request()
	require.NotNil(t, req)
	require.Equal(t, id, req.GetId(), "enclave must send the bare artifact id, not the full URL")
	require.Equal(t, storage_service.ArtifactType_ARTIFACT_TYPE_BINARY, req.GetType())
}
