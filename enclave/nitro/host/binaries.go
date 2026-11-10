package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	// it at a volume private to this host to keep it across container restarts.
	binaryCacheDir = flag.String("binary-cache-dir", os.Getenv("BINARY_CACHE_DIR"), "Root directory for per-enclave workflow binary caches, required for workflows. Reads BINARY_CACHE_DIR.")
	// binaryCacheMaxBytes bounds the on-disk cache. The volume is shared with
	// the node, so this must stay well inside its capacity.
	binaryCacheMaxBytes = flag.Int("binary-cache-max-bytes", binaryCacheLimitFromEnv(), "Max total size of the on-disk workflow binary cache. Zero uses settings maxCacheBytes or the default. Reads BINARY_CACHE_MAX_BYTES.")
)

func binaryCacheLimitFromEnv() int {
	limit, err := strconv.Atoi(os.Getenv("BINARY_CACHE_MAX_BYTES"))
	if err != nil {
		return 0
	}
	return limit
}

// newBinaryProvider requires a cache directory when storage is configured.
// Other apps need no provider. Workflow enclaves have no fetch fallback.
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
	return newBinaryProviderWithCache(parsed, filepath.Join(*binaryCacheDir, strconv.Itoa(*enclaveCID)), *binaryCacheMaxBytes, lggr)
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
	if parsed.StorageKey == "" && parsed.StorageServiceURL == "" {
		return parsed, false, nil
	}
	if parsed.StorageKey == "" || parsed.StorageServiceURL == "" {
		return parsed, false, errors.New("storageKey and storageServiceUrl are both required for binary fetching")
	}
	return parsed, true, nil
}

// binaryProvider fetches workflow binaries on the enclave's behalf and caches
// them on a node-local volume, so a restarted container does not re-download
// every binary and the enclave does not have to hold them all in RAM.
type binaryProvider struct {
	fetcher  *binaryfetch.BinaryFetcher
	raw      binaryfetch.RawFetcher
	timeout  time.Duration
	settings hostStorageSettings
}

// hostStorageSettings owns the startup storage fields of ENCLAVE_SETTINGS.
// The full payload is also forwarded verbatim to the enclave.
type hostStorageSettings struct {
	StorageKey         string          `json:"storageKey"`
	StorageServiceURL  string          `json:"storageServiceUrl"`
	StorageServiceTLS  bool            `json:"storageServiceTls"`
	MaxBinarySize      int64           `json:"maxBinarySize"`
	MaxCacheBytes      int             `json:"maxCacheBytes"`
	BinaryFetchTimeout storageDuration `json:"binaryFetchTimeout"`
}

// storageDuration preserves the settings contract: duration strings or nanoseconds.
type storageDuration time.Duration

func (d *storageDuration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parsing binaryFetchTimeout: %w", err)
		}
		*d = storageDuration(parsed)
		return nil
	}
	var ns int64
	if err := json.Unmarshal(b, &ns); err != nil {
		return err
	}
	*d = storageDuration(ns)
	return nil
}

// newBinaryProviderWithCache builds a provider for parsed storage settings,
// caching into cacheDir.
func newBinaryProviderWithCache(parsed hostStorageSettings, cacheDir string, maxCacheBytes int, lggr cllogger.SugaredLogger) (*binaryProvider, error) {
	timeout := types.DefaultBinaryFetchTimeout
	if parsed.BinaryFetchTimeout > 0 {
		timeout = time.Duration(parsed.BinaryFetchTimeout)
	}
	if maxCacheBytes < 0 {
		return nil, errors.New("binary-cache-max-bytes must be non-negative")
	}
	if maxCacheBytes == 0 {
		maxCacheBytes = parsed.MaxCacheBytes
		if maxCacheBytes <= 0 {
			maxCacheBytes = types.DefaultMaxBinaryCacheBytes
		}
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
		fetcher:  binaryfetch.NewBinaryFetcherWithStore(lggr, store, maxCacheBytes),
		raw:      raw,
		timeout:  timeout,
		settings: parsed,
	}, nil
}

// binaryFor returns a binary cached by hash, shared across workflows using the
// same artifact. The enclave independently verifies the signed binary_hash.
func (p *binaryProvider) binaryFor(ctx context.Context, execution *confworkflowtypes.WorkflowExecution) ([]byte, error) {
	if p == nil {
		return nil, errors.New("workflow binary fetching is not configured")
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

	binary, err := p.fetcher.Fetch(ctx, execution.GetBinaryUrl(), execution.GetBinaryHash(), p.raw)
	if err != nil {
		return nil, fmt.Errorf("fetching binary for workflow %s: %w", execution.GetWorkflowId(), err)
	}
	maxBytes := p.settings.MaxBinarySize
	if maxBytes <= 0 {
		maxBytes = types.DefaultMaxBinarySize
	}
	if int64(len(binary)) > maxBytes {
		return nil, fmt.Errorf("binary exceeds max size of %d bytes", maxBytes)
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
