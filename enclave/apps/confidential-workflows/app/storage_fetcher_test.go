package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
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
	// Capture the authority and authorization header for the proxy-path assertions.
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

	f, _, err := NewStorageFetcher(
		lis.Addr().String(), false, testStorageKeyHex, 0, 5*time.Second, logger.Test(t), httpSrv.Client(),
	)
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

func TestNewStorageFetcherRequiresArtifactHTTPClient(t *testing.T) {
	f, _, err := NewStorageFetcher(
		"127.0.0.1:1", false, testStorageKeyHex, 0, time.Second, logger.Test(t), nil,
	)
	require.Nil(t, f)
	require.EqualError(t, err, "artifact HTTP client is required")
}

func TestStorageFetcher_ProxyDialerPreservesAuthorityAndAuthorization(t *testing.T) {
	const storageAuthority = "storage.example.test:2222"

	// Start a local storage server behind a fake external authority.
	fake := &recordingStorage{url: "https://artifact.example/binary.wasm"}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	storage_service.RegisterNodeServiceServer(grpcSrv, fake)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	// Record the requested authority while forwarding to the local server.
	type dialAttempt struct {
		network string
		address string
	}
	dialed := make(chan dialAttempt, 1)
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case dialed <- dialAttempt{network: network, address: address}:
		default:
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", lis.Addr().String())
	}

	// Build the storage fetcher with the injected proxy dialer.
	f, pub, err := NewStorageFetcher(
		storageAuthority, false, testStorageKeyHex, 0, 5*time.Second, logger.Test(t), http.DefaultClient,
		WithStorageDialer(dialContext),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	// Resolve an artifact URL over the proxied gRPC connection.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gotURL, err := f.resolveURL(ctx, "artifact-id")
	require.NoError(t, err)
	require.Equal(t, fake.url, gotURL)

	// Confirm the dialer received the unresolved configured authority.
	select {
	case attempt := <-dialed:
		require.Equal(t, "tcp", attempt.network)
		require.Equal(t, storageAuthority, attempt.address)
	case <-time.After(time.Second):
		t.Fatal("storage dialer was not called")
	}

	// Confirm gRPC preserved the authority and sent a valid request-bound JWT.
	md := fake.requestMetadata()
	require.Equal(t, []string{storageAuthority}, md.Get(":authority"))
	token, err := nodeauthgrpc.ExtractBearerToken(metadata.NewIncomingContext(context.Background(), md))
	require.NoError(t, err)
	authenticator := (nodeauthjwt.NodeJWTAuthenticatorConfig{}).New(trustedKeyProvider{key: pub})
	valid, _, err := authenticator.AuthenticateJWT(context.Background(), token, fake.request())
	require.NoError(t, err)
	require.True(t, valid)
}
