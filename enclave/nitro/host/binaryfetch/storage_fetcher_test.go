package binaryfetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	nodeauthgrpc "github.com/smartcontractkit/chainlink-common/pkg/nodeauth/grpc"
	nodeauthjwt "github.com/smartcontractkit/chainlink-common/pkg/nodeauth/jwt"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type trustedKeyProvider struct {
	key ed25519.PublicKey
}

func (p trustedKeyProvider) IsNodePubKeyTrusted(_ context.Context, key ed25519.PublicKey) (bool, error) {
	return bytes.Equal(p.key, key), nil
}

// testStorageKeyHex is a deterministic ed25519 seed used to authenticate to the
// storage service in tests.
const testStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

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

// recordingStorage records DownloadArtifact requests and their gRPC metadata.
type recordingStorage struct {
	storage_service.UnimplementedNodeServiceServer
	url string

	mu           sync.Mutex
	lastReq      *storage_service.DownloadArtifactRequest
	lastMetadata metadata.MD
}

func (r *recordingStorage) DownloadArtifact(ctx context.Context, req *storage_service.DownloadArtifactRequest) (*storage_service.DownloadArtifactResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	r.mu.Lock()
	r.lastReq = req
	r.lastMetadata = md.Copy()
	r.mu.Unlock()
	return &storage_service.DownloadArtifactResponse{Url: r.url}, nil
}

func (r *recordingStorage) request() *storage_service.DownloadArtifactRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastReq
}

func (r *recordingStorage) requestMetadata() metadata.MD {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastMetadata.Copy()
}

// TestStorageFetcher_SendsBareArtifactID is the end-to-end regression guard: when
// FetchBinary is given a full BinaryUrl, the DownloadArtifactRequest that reaches
// the storage service must carry the bare artifact id and ARTIFACT_TYPE_BINARY,
// not the full URL.
func TestStorageFetcher_SendsBareArtifactID(t *testing.T) {
	const id = "00ff45641a2cb008d2cc7a8ad509671bf130b63e0dd3c1539dfa7dc61958b86d"
	locator := "https://storage.cre.stage.external.griddle.sh/artifacts/" + id + "/binary.wasm"
	rawBinary := []byte("wasm-bytes")

	httpSrv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
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

	f, pub, err := NewStorageFetcher(
		lis.Addr().String(), false, testStorageKeyHex, 0, 5*time.Second, logger.Test(t), httpSrv.Client(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	got, err := f.FetchBinary(context.Background(), locator)
	require.NoError(t, err)
	require.Equal(t, rawBinary, got)

	req := fake.request()
	require.NotNil(t, req)
	require.Equal(t, id, req.GetId(), "host must send the bare artifact id, not the full URL")
	require.Equal(t, storage_service.ArtifactType_ARTIFACT_TYPE_BINARY, req.GetType())

	md := fake.requestMetadata()
	require.Equal(t, []string{lis.Addr().String()}, md.Get(":authority"))
	token, err := nodeauthgrpc.ExtractBearerToken(metadata.NewIncomingContext(context.Background(), md))
	require.NoError(t, err)
	authenticator := (nodeauthjwt.NodeJWTAuthenticatorConfig{}).New(trustedKeyProvider{key: pub})
	valid, _, err := authenticator.AuthenticateJWT(context.Background(), token, req)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestNewStorageFetcherRequiresArtifactHTTPClient(t *testing.T) {
	f, _, err := NewStorageFetcher(
		"127.0.0.1:1", false, testStorageKeyHex, 0, time.Second, logger.Test(t), nil,
	)
	require.Nil(t, f)
	require.EqualError(t, err, "artifact HTTP client is required")
}

func TestStorageFetcher_DownloadSizeBound(t *testing.T) {
	for _, size := range []int{3, 4, 5} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			binary := bytes.Repeat([]byte("x"), size)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(binary)))
			}))
			defer srv.Close()
			fetcher := &StorageFetcher{httpClient: srv.Client(), maxBytes: 4, lggr: logger.Test(t)}
			got, err := fetcher.Download(t.Context(), srv.URL)
			if size > 4 {
				require.ErrorContains(t, err, "exceeds max size")
			} else {
				require.NoError(t, err)
				require.Equal(t, binary, got)
			}
		})
	}
}
