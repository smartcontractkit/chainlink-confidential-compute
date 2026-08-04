package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WorkflowSettings is the runtime config + secrets contract of this app. The
// host injects it as opaque JSON over vsock (POST /settings) and forwards it
// verbatim, so this app is the sole owner of the schema. A Nitro EIF is measured
// (PCR), so environment-specific endpoints and tunables cannot be baked in
// without changing the attestation; they are supplied at runtime instead,
// keeping one EIF usable across environments.
//
// Every injection carries the complete configuration: StorageKey,
// StorageServiceURL and GatewayURL are required and a payload missing any of
// them is rejected whole, rather than leaving the app half-configured. The
// remaining fields are tunables that fall back to their built-in defaults when
// omitted. Unknown fields are ignored, so a payload written for a newer app can
// still be injected into an older one.
//
//   - StorageKey: hex ed25519 key (32-byte seed or 64-byte full) the enclave
//     uses to authenticate CRE storage-service DownloadArtifact calls.
//   - StorageServiceURL / StorageServiceTLS: the storage-service gRPC endpoint
//     the enclave fetches workflow binaries from.
//   - GatewayURL: the Gateway endpoint(s) for remote dispatch (dynamic secrets +
//     capability calls). Accepts a comma-separated list; the enclave round-robins
//     across them and fails over to the next on a transport/proxy error.
//   - MaxBinarySize: max decompressed workflow-binary size accepted from
//     storage, in bytes. Zero falls back to the enclave's built-in default.
//   - BinaryFetchTimeout: per-fetch timeout for downloading a workflow binary.
//     Zero falls back to the enclave's built-in default.
//   - MaxCacheBytes: size bound of the verified-binary LRU cache, in bytes.
//     Zero falls back to the enclave's built-in default.
//   - RequestTimeout: global request timeout inside the enclave, used as the
//     default deadline for outbound HTTP a workflow makes while being served.
//     Should track the caller's enclave request timeout, since work outliving
//     that deadline is work nobody is waiting for. Zero falls back to the
//     enclave's built-in default.
//   - GatewayRequestTimeout: HTTP client timeout for enclave->gateway requests
//     (dynamic secrets + capability calls). Should not exceed RequestTimeout:
//     the gateway call is nested inside the enclave's own request lifecycle.
//     Zero falls back to the enclave's built-in default.
//   - ExecutionTimeout: wall-clock bound on a single workflow execution (the
//     WASM module run). Caps how long a hung or runaway workflow holds one of
//     the enclave's bounded execution slots. Zero falls back to the WASM host's
//     built-in default, which is 10 minutes.
//   - WorkflowGracePeriod: how long each validated execution waits before it
//     starts running. Zero falls back to types.DefaultWorkflowGracePeriod; a
//     negative value disables the wait.
type WorkflowSettings struct {
	StorageKey            string   `json:"storageKey"`
	StorageServiceURL     string   `json:"storageServiceUrl"`
	StorageServiceTLS     bool     `json:"storageServiceTls,omitempty"`
	GatewayURL            string   `json:"gatewayUrl"`
	MaxBinarySize         int64    `json:"maxBinarySize,omitempty"`
	BinaryFetchTimeout    Duration `json:"binaryFetchTimeout,omitempty"`
	MaxCacheBytes         int64    `json:"maxCacheBytes,omitempty"`
	RequestTimeout        Duration `json:"requestTimeout,omitempty"`
	GatewayRequestTimeout Duration `json:"gatewayRequestTimeout,omitempty"`
	ExecutionTimeout      Duration `json:"executionTimeout,omitempty"`
	WorkflowGracePeriod   Duration `json:"workflowGracePeriod,omitempty"`
}

// validate reports the required settings the payload left empty. The enclave
// cannot fetch a workflow binary without the storage endpoint and key, and
// cannot reach dynamic secrets or remote capabilities without a gateway, so a
// payload missing any of them is a deployment error worth failing on at
// injection time instead of surfacing as a failed execution later.
func (s *WorkflowSettings) validate() error {
	var missing []string
	if s.StorageKey == "" {
		missing = append(missing, "storageKey")
	}
	if s.StorageServiceURL == "" {
		missing = append(missing, "storageServiceUrl")
	}
	if s.GatewayURL == "" {
		missing = append(missing, "gatewayUrl")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Duration is a time.Duration that unmarshals from either a Go duration string
// ("80s") or a plain number of nanoseconds, so hand-written deployment config
// can use the readable form.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parsing duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var ns int64
	if err := json.Unmarshal(b, &ns); err != nil {
		return fmt.Errorf("parsing duration: %w", err)
	}
	*d = Duration(ns)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}
