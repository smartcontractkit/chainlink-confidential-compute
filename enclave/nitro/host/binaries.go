package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/host/binaryfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

var (
	// binaryCacheDir is where the host caches fetched workflow binaries. Point
	// it at a mounted volume to keep the cache across container restarts; empty
	// disables host-side fetching and leaves the enclave to fetch its own.
	binaryCacheDir = flag.String("binary-cache-dir", os.Getenv("BINARY_CACHE_DIR"), "Directory for the workflow binary cache. Empty disables host-side binary fetching. Reads BINARY_CACHE_DIR.")
	// binaryCacheMaxBytes bounds the on-disk cache. The volume is shared with
	// the node, so this must stay well inside its capacity.
	binaryCacheMaxBytes = flag.Int("binary-cache-max-bytes", util.EnvInt("BINARY_CACHE_MAX_BYTES", types.DefaultMaxBinaryCacheBytes), "Max total size of the on-disk workflow binary cache. Reads BINARY_CACHE_MAX_BYTES.")
)

// newBinaryProvider builds the binary provider from the binary-cache flags
// and the settings payload. It returns nil (logging why) when host-side
// fetching is disabled or could not be set up, leaving the enclave to fetch
// binaries itself, so failure here is never fatal.
func newBinaryProvider(settings string, lggr cllogger.SugaredLogger) *binaryProvider {
	if *binaryCacheDir == "" {
		return nil
	}
	provider, err := newBinaryProviderWithCache(settings, *binaryCacheDir, *binaryCacheMaxBytes, lggr)
	if err != nil {
		lggr.Errorw("host binary fetching disabled, enclave will fetch its own", "error", err)
		return nil
	}
	return provider
}

// binaryProvider fetches workflow binaries on the enclave's behalf and caches
// them on a node-local volume, so a restarted container does not re-download
// every binary and the enclave does not have to hold them all in RAM.
//
// It is best-effort by construction: every failure path returns no binary and
// the enclave falls back to fetching the binary itself.
type binaryProvider struct {
	fetcher *binaryfetch.BinaryFetcher
	raw     binaryfetch.RawFetcher
	timeout time.Duration
	logger  cllogger.SugaredLogger
}

// hostStorageSettings is the subset of ENCLAVE_SETTINGS the host needs to fetch
// binaries itself. The enclave app owns the full schema and still receives the
// payload verbatim; these fields are read, not consumed.
type hostStorageSettings struct {
	StorageKey         string `json:"storageKey"`
	StorageServiceURL  string `json:"storageServiceUrl"`
	StorageServiceTLS  bool   `json:"storageServiceTls"`
	MaxBinarySize      int64  `json:"maxBinarySize"`
	BinaryFetchTimeout string `json:"binaryFetchTimeout"`
}

// newBinaryProviderWithCache builds a provider from the settings payload and an
// explicit cache location. It returns a nil provider (with no error) when the
// settings carry no storage credentials, which is the case for apps that do
// not execute workflow binaries.
func newBinaryProviderWithCache(settings string, cacheDir string, maxCacheBytes int, lggr cllogger.SugaredLogger) (*binaryProvider, error) {
	if strings.TrimSpace(settings) == "" {
		return nil, nil
	}

	var parsed hostStorageSettings
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return nil, fmt.Errorf("parsing settings for binary fetching: %w", err)
	}
	if parsed.StorageKey == "" || parsed.StorageServiceURL == "" {
		return nil, nil
	}

	timeout := types.DefaultBinaryFetchTimeout
	if parsed.BinaryFetchTimeout != "" {
		d, err := time.ParseDuration(parsed.BinaryFetchTimeout)
		if err != nil {
			return nil, fmt.Errorf("parsing binaryFetchTimeout: %w", err)
		}
		timeout = d
	}

	store, err := binaryfetch.NewDiskStore(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("opening binary cache: %w", err)
	}

	// Unlike the enclave, the host reaches the storage service directly: it is
	// already outside the TEE and owns the egress path.
	raw, pub, err := binaryfetch.NewStorageFetcher(
		parsed.StorageServiceURL,
		parsed.StorageServiceTLS,
		parsed.StorageKey,
		parsed.MaxBinarySize,
		timeout,
		lggr,
		util.NewRestrictedHTTPClient(),
	)
	if err != nil {
		return nil, fmt.Errorf("building storage fetcher: %w", err)
	}

	lggr.Infow("host binary fetching enabled",
		"cacheDir", cacheDir,
		"maxCacheBytes", maxCacheBytes,
		"storageServiceUrl", parsed.StorageServiceURL,
		"storageIdentity", hex.EncodeToString(pub))

	return &binaryProvider{
		fetcher: binaryfetch.NewBinaryFetcherWithStore(lggr, store, maxCacheBytes),
		raw:     raw,
		timeout: timeout,
		logger:  lggr,
	}, nil
}

// binaryFor returns the workflow binary for a decoded execution. An incomplete
// payload yields (nil, nil): the enclave validates the payload and reports the
// real error. A fetch failure yields the error, which fails the request rather
// than degrading to the enclave's own fetch against the same storage service.
//
// The cache is keyed by workflow ID: a workflow ID commits to its binary
// (GenerateWorkflowID hashes the binary), so the mapping is stable. The enclave
// re-verifies against the signed binary_hash regardless, so a stale or poisoned
// cache entry fails closed rather than executing.
func (p *binaryProvider) binaryFor(ctx context.Context, execution *confworkflowtypes.WorkflowExecution) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	if execution.GetWorkflowId() == "" || execution.GetBinaryUrl() == "" || len(execution.GetBinaryHash()) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	binary, err := p.fetcher.Fetch(ctx, cacheKey(execution.GetWorkflowId()), execution.GetBinaryUrl(), execution.GetBinaryHash(), p.raw)
	if err != nil {
		return nil, fmt.Errorf("fetching binary for workflow %s: %w", execution.GetWorkflowId(), err)
	}
	return binary, nil
}

// Close releases the storage connection.
func (p *binaryProvider) Close() error {
	if p == nil {
		return nil
	}
	return p.raw.Close()
}

// cacheKey renders a workflow ID as a cache key. Workflow IDs are hex, but the
// value is untrusted, so anything unexpected is hex-encoded rather than trusted
// as a filename.
func cacheKey(workflowID string) string {
	if _, err := hex.DecodeString(workflowID); err == nil {
		return workflowID
	}
	return hex.EncodeToString([]byte(workflowID))
}
