package app

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
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
		lis.Addr().String(), false, testStorageKeyHex, 0, 5*time.Second, logger.Test(t),
		WithStorageHTTPClient(httpSrv.Client()),
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

func TestValidateArtifactURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "https", raw: "https://artifacts.example/binary.wasm"},
		{name: "custom https port", raw: "https://artifacts.example:8443/binary.wasm"},
		{name: "http", raw: "http://artifacts.example/binary.wasm", wantErr: true},
		{name: "credentials", raw: "https://user:secret@artifacts.example/binary.wasm", wantErr: true},
		{name: "missing host", raw: "https:///binary.wasm", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u, err := neturl.Parse(test.raw)
			require.NoError(t, err)
			err = validateArtifactURL(u, false)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateArtifactURLAllowsHTTPOnlyForTests(t *testing.T) {
	u, err := neturl.Parse("http://127.0.0.1:8080/binary.wasm")
	require.NoError(t, err)
	require.Error(t, validateArtifactURL(u, false))
	require.NoError(t, validateArtifactURL(u, true))
}

// The artifact URL is storage-supplied, so its redirect policy is the untrusted
// edge of this path: every hop is validated, and the chain is bounded. Both are
// installed by a CheckRedirect hook, which is also what removes net/http's own
// ceiling, so neither is covered by testing validateArtifactURL alone.
func TestStorageFetcher_ArtifactRedirectPolicy(t *testing.T) {
	newFetcher := func(t *testing.T, srv *httptest.Server) *StorageFetcher {
		t.Helper()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		grpcSrv := grpc.NewServer()
		storage_service.RegisterNodeServiceServer(grpcSrv, &recordingStorage{url: srv.URL})
		go func() { _ = grpcSrv.Serve(lis) }()
		t.Cleanup(grpcSrv.Stop)

		f, _, err := NewStorageFetcher(
			lis.Addr().String(), false, testStorageKeyHex, 0, 30*time.Second, logger.Test(t),
			WithStorageHTTPClient(srv.Client()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	t.Run("chain is bounded", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			// Always redirect, so only the ceiling can stop it.
			http.Redirect(rw, r, srv.URL+"/next", http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		_, err := newFetcher(t, srv).FetchBinary(context.Background(), srv.URL+"/binary.wasm")
		require.Error(t, err)
		require.Contains(t, err.Error(), "stopped after")
	})

	t.Run("a caller's redirect policy cannot remove the bound", func(t *testing.T) {
		// The cap must run before delegating. srv.Client() has a nil
		// CheckRedirect, so the subtests above never reach the delegation branch
		// and would stay green if the ordering regressed.
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, srv.URL+"/next", http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		permissive := srv.Client()
		permissive.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }

		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		grpcSrv := grpc.NewServer()
		storage_service.RegisterNodeServiceServer(grpcSrv, &recordingStorage{url: srv.URL})
		go func() { _ = grpcSrv.Serve(lis) }()
		t.Cleanup(grpcSrv.Stop)

		f, _, err := NewStorageFetcher(
			lis.Addr().String(), false, testStorageKeyHex, 0, 30*time.Second, logger.Test(t),
			WithStorageHTTPClient(permissive),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })

		_, err = f.FetchBinary(context.Background(), srv.URL+"/binary.wasm")
		require.Error(t, err)
		require.Contains(t, err.Error(), "stopped after")
	})

	t.Run("every hop is validated", func(t *testing.T) {
		// A hop that downgrades to plain HTTP must be refused even though the
		// initial URL passed.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, "http://example.invalid/binary.wasm", http.StatusFound)
		}))
		t.Cleanup(srv.Close)

		_, err := newFetcher(t, srv).FetchBinary(context.Background(), srv.URL+"/binary.wasm")
		require.Error(t, err)
		require.Contains(t, err.Error(), "HTTPS")
	})
}
