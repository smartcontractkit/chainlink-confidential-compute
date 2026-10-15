package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// newBinaryProvider builds the binary provider from the binary-cache flags and
// the settings payload.
//
// It returns a nil provider (with no error) only when the settings carry no
// storage credentials, which means the app does not execute workflow binaries.
// Settings that DO carry them with no cache directory configured is a
// deployment mistake, not a degraded mode: the enclave cannot fetch for itself,
// so every execution would fail. That returns an error and the host refuses to
// start, which surfaces the missing config immediately instead of as a steady
// stream of failed workflows.
func newBinaryProvider(settings string, lggr cllogger.SugaredLogger) (*binaryProvider, error) {
	parsed, ok, err := parseHostStorageSettings(settings)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if *binaryCacheDir == "" {
		return nil, errors.New("settings carry storage credentials but no binary cache directory is configured; set BINARY_CACHE_DIR")
	}
	return newBinaryProviderWithCache(parsed, *binaryCacheDir, *binaryCacheMaxBytes, lggr)
}

// parseHostStorageSettings extracts the storage fields the host needs. ok is
// false when the payload carries no storage credentials at all.
func parseHostStorageSettings(settings string) (hostStorageSettings, bool, error) {
	var parsed hostStorageSettings
	if strings.TrimSpace(settings) == "" {
		return parsed, false, nil
	}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return parsed, false, fmt.Errorf("parsing settings for binary fetching: %w", err)
	}
	if parsed.StorageKey == "" || parsed.StorageServiceURL == "" {
		return parsed, false, nil
	}
	return parsed, true, nil
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

// newBinaryProviderWithCache builds a provider for parsed storage settings,
// caching into cacheDir.
func newBinaryProviderWithCache(parsed hostStorageSettings, cacheDir string, maxCacheBytes int, lggr cllogger.SugaredLogger) (*binaryProvider, error) {
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
	// already outside the TEE and owns the egress path. The artifact client is
	// SSRF-restricted (HTTPS only, no private addresses); e2e runs against a
	// loopback fake storage service over plain HTTP, so they set the same
	// OUTBOUND_ALLOW_LOCAL_FOR_TESTS escape hatch the SOCKS proxy honors.
	artifactClient := types.HTTPClient(util.NewRestrictedHTTPClient())
	if *outboundAllowLocalForTests {
		artifactClient = util.NewUnrestrictedClient()
	}
	raw, pub, err := binaryfetch.NewStorageFetcher(
		parsed.StorageServiceURL,
		parsed.StorageServiceTLS,
		parsed.StorageKey,
		parsed.MaxBinarySize,
		timeout,
		lggr,
		artifactClient,
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

// binaryFor returns the workflow binary for a decoded execution. Every failure
// is an error: the enclave has no fetch path of its own, so a request that
// reaches here without a usable binary cannot execute, and reporting why at the
// host beats a bare "no binary supplied" from inside the enclave.
//
// The cache is keyed by workflow ID: a workflow ID commits to its binary
// (GenerateWorkflowID hashes the binary), so the mapping is stable. The enclave
// re-verifies against the signed binary_hash regardless, so a stale or poisoned
// cache entry fails closed rather than executing.
func (p *binaryProvider) binaryFor(ctx context.Context, execution *confworkflowtypes.WorkflowExecution) ([]byte, error) {
	if p == nil {
		// Startup already rejected settings that need fetching without a cache
		// directory, so a nil provider here means the deployment carries no
		// storage credentials at all and runs no workflow binaries.
		return nil, nil
	}
	var missing []string
	if execution.GetWorkflowId() == "" {
		missing = append(missing, "workflow_id")
	}
	if execution.GetBinaryUrl() == "" {
		missing = append(missing, "binary_url")
	}
	if len(execution.GetBinaryHash()) == 0 {
		missing = append(missing, "binary_hash")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("workflow execution is missing %s", strings.Join(missing, ", "))
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
