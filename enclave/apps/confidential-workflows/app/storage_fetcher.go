package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"path"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	nodeauthgrpc "github.com/smartcontractkit/chainlink-common/pkg/nodeauth/grpc"
	nodeauthjwt "github.com/smartcontractkit/chainlink-common/pkg/nodeauth/jwt"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// RawFetcher resolves a storage locator to the raw workflow-binary bytes. It
// does NOT verify binary_hash; the caller (BinaryFetcher) does, so the storage
// service is untrusted for integrity.
type RawFetcher interface {
	FetchBinary(ctx context.Context, locator string) ([]byte, error)
	Close() error
}

// StorageFetcher fetches the workflow binary directly from the CRE storage
// service, from inside the enclave: it calls NodeService.DownloadArtifact over
// JWT-authed gRPC (the JWT is EdDSA-signed with the injected ed25519 storage
// key) to obtain a pre-signed URL, then downloads that URL. This is the code
// that previously lived in the host-agent sidecar; it now runs in the TEE so
// the fetch is authenticated by the enclave itself.
type StorageFetcher struct {
	conn       *grpc.ClientConn
	client     storage_service.NodeServiceClient
	jwtGen     nodeauthjwt.JWTGenerator
	httpClient *http.Client
	maxBytes   int64
	timeout    time.Duration
	lggr       logger.Logger
}

var _ RawFetcher = (*StorageFetcher)(nil)

// newJWTGenerator builds a NodeService JWT generator from a hex-encoded ed25519
// private key. The key's public half is what the storage service whitelists; it
// is carried as the JWT Issuer/Subject (see nodeauth/jwt). Accepts either a
// 32-byte seed or a 64-byte full ed25519 private key.
func newJWTGenerator(privKeyHex string) (nodeauthjwt.JWTGenerator, ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(privKeyHex), "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("decoding ed25519 key hex: %w", err)
	}

	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize: // 32
		priv = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize: // 64
		priv = ed25519.PrivateKey(raw)
	default:
		return nil, nil, fmt.Errorf("ed25519 key must be %d (seed) or %d (full) bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}

	pub := priv.Public().(ed25519.PublicKey)
	account := hex.EncodeToString(pub)

	signFn := func(_ context.Context, _ string, data []byte) ([]byte, error) {
		return ed25519.Sign(priv, data), nil
	}
	signer, err := core.NewEd25519Signer(account, signFn)
	if err != nil {
		return nil, nil, fmt.Errorf("building ed25519 signer: %w", err)
	}

	return nodeauthjwt.NewNodeJWTGenerator(signer, pub), pub, nil
}

// NewStorageFetcher parses the ed25519 key, dials the storage service, and
// prepares the JWT generator. It returns the derived public key so the caller
// can log which identity is being used (the pubkey whitelisted by storage).
func NewStorageFetcher(storageURL string, tls bool, privKeyHex string, maxBytes int64, timeout time.Duration, lggr logger.Logger) (*StorageFetcher, ed25519.PublicKey, error) {
	if storageURL == "" {
		return nil, nil, fmt.Errorf("storage service url is required")
	}

	jwtGen, pub, err := newJWTGenerator(privKeyHex)
	if err != nil {
		return nil, nil, err
	}

	var creds credentials.TransportCredentials
	if tls {
		creds = credentials.NewTLS(nil)
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(storageURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("dialing storage service %q: %w", storageURL, err)
	}

	if maxBytes <= 0 {
		maxBytes = types.DefaultMaxBinarySize
	}
	if timeout <= 0 {
		timeout = types.DefaultBinaryFetchTimeout
	}

	return &StorageFetcher{
		conn:       conn,
		client:     storage_service.NewNodeServiceClient(conn),
		jwtGen:     jwtGen,
		httpClient: &http.Client{},
		maxBytes:   maxBytes,
		timeout:    timeout,
		lggr:       lggr,
	}, pub, nil
}

// FetchBinary returns the raw bytes of the workflow binary identified by locator
// (WorkflowExecution.BinaryUrl, a full artifact URL from which the storage-service
// artifact id is extracted).
func (f *StorageFetcher) FetchBinary(ctx context.Context, locator string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	url, err := f.resolveURL(ctx, locator)
	if err != nil {
		return nil, fmt.Errorf("resolving artifact %q: %w", locator, err)
	}
	return f.download(ctx, url)
}

// artifactID extracts the storage-service artifact id from a binary locator.
// WorkflowExecution.BinaryUrl is a full URL like
// https://<host>/artifacts/<id>/binary.wasm, but DownloadArtifact expects the
// bare <id>. If locator is already an id (no URL scheme), it is returned as-is.
func artifactID(locator string) string {
	if !strings.Contains(locator, "://") {
		return locator
	}
	u, err := neturl.Parse(locator)
	if err != nil {
		return locator
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, s := range segments {
		if s == "artifacts" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	// Fallback: .../<id>/binary.wasm -> <id>
	return path.Base(path.Dir(u.Path))
}

// resolveURL calls DownloadArtifact with a JWT to obtain the pre-signed URL.
func (f *StorageFetcher) resolveURL(ctx context.Context, locator string) (string, error) {
	req := &storage_service.DownloadArtifactRequest{
		Id:   artifactID(locator),
		Type: storage_service.ArtifactType_ARTIFACT_TYPE_BINARY,
	}

	authCtx, err := f.withJWT(ctx, req)
	if err != nil {
		return "", err
	}

	resp, err := f.client.DownloadArtifact(authCtx, req)
	if err != nil {
		return "", fmt.Errorf("DownloadArtifact: %w", err)
	}
	if resp.GetUrl() == "" {
		return "", fmt.Errorf("storage service returned empty url")
	}
	return resp.GetUrl(), nil
}

// withJWT mints a JWT bound to req and attaches it to the outgoing gRPC metadata
// as "authorization: Bearer <jwt>", matching the storage service token extractor.
func (f *StorageFetcher) withJWT(ctx context.Context, req any) (context.Context, error) {
	token, err := f.jwtGen.CreateJWTForRequest(req)
	if err != nil {
		return nil, fmt.Errorf("creating JWT: %w", err)
	}
	return metadata.AppendToOutgoingContext(ctx, nodeauthgrpc.AuthorizationHeader, nodeauthgrpc.BearerPrefix+token), nil
}

// download GETs the pre-signed URL and returns the body, size-limited.
func (f *StorageFetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building download request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading binary: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			f.lggr.Warnf("closing download body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading binary: status %d", resp.StatusCode)
	}

	// The storage service serves the artifact base64-encoded (this is what the
	// workflow syncer expects too). Decode to the raw bytes that binary_hash
	// covers. base64 inflates by ~4/3, so cap the encoded read accordingly.
	maxEncoded := f.maxBytes*4/3 + 4
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, maxEncoded+1))
	if err != nil {
		return nil, fmt.Errorf("reading binary body: %w", err)
	}
	if int64(len(encoded)) > maxEncoded {
		return nil, fmt.Errorf("binary exceeds max size of %d bytes", f.maxBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding binary: %w", err)
	}
	return decoded, nil
}

// Close releases the gRPC connection.
func (f *StorageFetcher) Close() error {
	return f.conn.Close()
}
