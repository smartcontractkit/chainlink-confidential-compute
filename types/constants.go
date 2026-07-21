package types

import "time"

const (
	AppIDConfidentialHTTP      = "confidential-http@1.0.0-alpha"
	AppIDConfidentialWorkflows = "confidential-workflows@1.0.0-alpha"
	AppIDConfidentialEcho      = "confidential-echo@1.0.0-alpha"
)

// Relevant constants for Confidential Compute, beneficial to be examined next to each other to understand end-to-end behavior.
const (
	// Enclave ephemeral public key caching
	DefaultEnablePublicKeyCache                 = true
	DefaultEnablePublicKeyCacheProactiveRefresh = true
	DefaultPublicKeyCacheTTL                    = 5 * time.Minute
	DefaultRefreshIntervalPercent               = 0
	DefaultMinRefreshInterval                   = 10 * time.Second

	// Ephemeral keypair rotation and expiration
	DefaultKeypairRotationFrequency = 12 * time.Hour
	DefaultKeypairExpiration        = 24 * time.Hour

	// MaxRequestKeyMapEntries caps the number of requestID->keypair mappings the
	// keychain retains; past the cap it evicts the oldest-inserted entries.
	MaxRequestKeyMapEntries = 100_000

	// PublicKeyAttestationCacheTTL bounds how long the enclave reuses a cached
	// attested /publicKeys response.
	PublicKeyAttestationCacheTTL = 5 * time.Second

	// MaxReplayCacheEntries caps the enclave server's executed and in-progress
	// request caches. Evicting an executed-request hash early re-opens that
	// request to replay, so the cap must stay far above real traffic.
	MaxReplayCacheEntries = 500_000

	// Vault DON secrets caching
	DefaultEnableSecretsCache = false

	// Global default cache TTL. Determines:
	// - Vault DON secrets caching TTL if enabled.
	DefaultCacheTTL = 24 * time.Hour

	// Enclave communication timeouts
	DefaultEnclaveRequestTimeout   = 30 * time.Second
	DefaultPublicKeyRequestTimeout = 5 * time.Second
	// DefaultGatewayRequestTimeout caps a single enclave->gateway HTTP exchange
	// (connect + send + read). The gateway call is nested inside the enclave's
	// own request lifecycle (the enclave reaches out to the gateway while
	// serving a request that is itself bounded by EnclaveRequestTimeout), so
	// the gateway timeout must not exceed it: a longer cap would only keep
	// waiting past the point the caller already gave up. Defaults to
	// DefaultEnclaveRequestTimeout; overridable per-deployment via
	// gateway.WithTimeout.
	DefaultGatewayRequestTimeout = DefaultEnclaveRequestTimeout

	// Workflow-binary fetch & cache defaults. Each is overridable per-deployment
	// at runtime via SettingsRequest (host injects them over vsock); these values
	// apply only when the corresponding setting is left unset.
	//
	// DefaultMaxBinarySize bounds the workflow binary accepted from storage.
	DefaultMaxBinarySize = 20 * 1024 * 1024 // 20 MB (matches chainlink-common default)
	// DefaultBinaryFetchTimeout bounds a single workflow-binary download.
	DefaultBinaryFetchTimeout = 60 * time.Second
	// DefaultMaxBinaryCacheBytes bounds the enclave's verified-binary LRU cache.
	DefaultMaxBinaryCacheBytes = 256 * 1024 * 1024 // 256 MB

	// Enclave inbound proxy timeouts & caching
	InboundProxyRequestCacheTTL = 5 * time.Minute
	QuorumTimeout               = 20 * time.Second

	// ConfigVoteTTL bounds how long the enclave retains a pending config-update
	// vote before it expires. Votes for the same proposed config must accumulate
	// to quorum within this window.
	ConfigVoteTTL = 10 * time.Minute

	// MaxInboundRequestBodyBytes bounds the request body the host accepts on
	// its /requests and /config handlers before buffering it. A SignedComputeRequest
	// has several unbounded fields (ciphertexts, O(n*m*k) decryption-key shares),
	// so a compromised API key or malicious DON node could otherwise send a
	// multi-GB payload and OOM the host before signature verification rejects it.
	// Sized generously to never sever a legitimate batched request.
	MaxInboundRequestBodyBytes = 64 << 20

	// MaxEnclaveResponseBodyBytes bounds response bodies that enclave-path
	// clients read from untrusted peers (gateway, peer enclaves) before
	// buffering them in memory, so a malicious or buggy peer cannot trigger
	// OOM by returning an arbitrarily large body.
	MaxEnclaveResponseBodyBytes = 10 << 20

	// MaxHTTPResponseBodyBytes bounds response bodies read from arbitrary
	// upstream endpoints by the outbound HTTP capabilities (confidential-http
	// and the confidential-workflows http-actions path), so a large response
	// cannot exhaust enclave memory.
	MaxHTTPResponseBodyBytes = 1000 * 1024

	// Enclave app user-facing error messages (shared between enclave app and executor)
	ErrEncryptionRequestedNoKey = "encryption requested but no AES-GCM key in secrets"
	ErrKeyPresentNoEncryption   = "AES-GCM key present but encryption not requested"
	ErrResponseBodyTooLarge     = "response body exceeds maximum allowed size"
	ErrQuorumTimeout            = "quorum_timeout"

	// ErrVaultSystemErrorFallback is the literal string the chainlink core vault plugin returns
	// in SecretResponse.Error for any non-user-classified failure. See userFacingError() in
	// chainlink core's ocr2 vault plugin: typed *userError values pass through; everything else
	// gets replaced with this fallback before crossing the wire. The CC framework pattern-matches
	// on it to distinguish system from user errors at its boundary.
	// TODO: replace this string match with a typed origin/code field on SecretResponse.
	ErrVaultSystemErrorFallback = "failed to handle get secret request"
)

// ServiceConfidentialComputeVersion is the global version for Confidential Compute releases.
// We are not using CRE versioning for this, as updating that version implies changes to the CRE SDK.
// TODO: remove `ServiceConfidentialComputeVersionLegacy` once we finish migrating away from including `Version`
// in the compute request hash.
const ServiceConfidentialComputeVersion = "0.0.6"
const ServiceConfidentialComputeVersionLegacy = "0.0.6"
