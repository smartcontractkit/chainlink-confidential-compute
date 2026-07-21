package types

import "time"

// WorkflowSettings is the runtime config + secrets contract shared between the
// confidential-workflows enclave app (which unmarshals it) and the host settings
// injector (which builds it from its individual flags). A Nitro EIF is measured
// (PCR), so environment-specific endpoints and tunables cannot be baked in
// without changing the attestation; they are supplied at runtime instead,
// keeping one EIF usable across environments.
//
//   - StorageKey: hex ed25519 key (32-byte seed or 64-byte full) the enclave
//     uses to authenticate CRE storage-service DownloadArtifact calls.
//   - StorageServiceURL / StorageServiceTLS: the storage-service gRPC endpoint
//     the enclave fetches workflow binaries from.
//   - GatewayURL: the Gateway endpoint(s) for remote dispatch (dynamic secrets +
//     capability calls). Accepts a comma-separated list; the enclave round-robins
//     across them and fails over to the next on a transport/proxy error. Empty
//     leaves the enclave in local-only mode.
//   - MaxBinarySize: max decompressed workflow-binary size accepted from
//     storage, in bytes. Zero falls back to the enclave's built-in default.
//   - BinaryFetchTimeout: per-fetch timeout for downloading a workflow binary.
//     Zero falls back to the enclave's built-in default.
//   - MaxCacheBytes: size bound of the verified-binary LRU cache, in bytes.
//     Zero falls back to the enclave's built-in default.
//
// TODO: this type lives here only so the host can build the payload from its
// individual settings flags. Once those flags are deprecated in favor of the
// host forwarding raw --settings JSON verbatim, the host no longer needs the
// type and it should move back into the confidential-workflows app.go, where it
// is the only consumer.
type WorkflowSettings struct {
	StorageKey         string        `json:"storageKey"`
	StorageServiceURL  string        `json:"storageServiceUrl,omitempty"`
	StorageServiceTLS  bool          `json:"storageServiceTls,omitempty"`
	GatewayURL         string        `json:"gatewayUrl,omitempty"`
	MaxBinarySize      int64         `json:"maxBinarySize,omitempty"`
	BinaryFetchTimeout time.Duration `json:"binaryFetchTimeout,omitempty"`
	MaxCacheBytes      int64         `json:"maxCacheBytes,omitempty"`
}
