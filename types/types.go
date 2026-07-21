package types

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"net/http"
	"time"
)

type Logger interface {
	Debugw(msg string, keysAndValues ...any)
	Infow(msg string, keysAndValues ...any)
	Warnw(msg string, keysAndValues ...any)
	Errorw(msg string, keysAndValues ...any)
}

const (
	PostmanEchoURL      = "https://postman-echo.com/"
	StickySessionHeader = "Sticky-Session-A"
)

const DomainSeparator = "CONFIDENTIAL_COMPUTE_PAYLOAD"
const AESGCMEncryptionKey = "san_marino_aes_gcm_encryption_key"

const (
	PublicKeyPath = "/publicKeys"
	ExecutePath   = "/requests"
	SetConfigPath = "/config"
	MemoryPath    = "/memory"
	SettingsPath  = "/settings"
)

// SettingsRequest carries runtime config + secrets injected into the enclave
// by the host-side settings injector over vsock (never proxied to the external
// network). A Nitro EIF is measured (PCR), so environment-specific endpoints
// and tunables cannot be baked in without changing the attestation; they are
// supplied here at runtime instead, keeping one EIF usable across environments.
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
type SettingsRequest struct {
	StorageKey         string        `json:"storageKey"`
	StorageServiceURL  string        `json:"storageServiceUrl,omitempty"`
	StorageServiceTLS  bool          `json:"storageServiceTls,omitempty"`
	GatewayURL         string        `json:"gatewayUrl,omitempty"`
	MaxBinarySize      int64         `json:"maxBinarySize,omitempty"`
	BinaryFetchTimeout time.Duration `json:"binaryFetchTimeout,omitempty"`
	MaxCacheBytes      int64         `json:"maxCacheBytes,omitempty"`
}

type EnclaveType string

const (
	EnclaveTypeNitro EnclaveType = "NITRO"
	EnclaveTypeSGX   EnclaveType = "SGX"
	EnclaveTypeTDX   EnclaveType = "TDX"
	EnclaveTypeSEV   EnclaveType = "SEV"
	EnclaveTypeFake  EnclaveType = "FAKE"
)

// Fake enclave environment constants. The fake environment emulates a real TEE
// (e.g. Nitro) for local development and E2E tests without enclave hardware.
const (
	// FakeAttestationDocument is the canonical attestation payload produced by
	// the fake attestor and accepted by the client when validating a fake
	// enclave. It stands in for a real attestation document.
	FakeAttestationDocument = "fake-attestation"

	// FakeMeasurements is the placeholder measurements value advertised for fake
	// enclaves. Fake attestation validation ignores measurements, so the value
	// is arbitrary but unified here for reference.
	FakeMeasurements = "fake-measurements"
)

// Fake enclave runtime environment variables. These form the contract between
// the build-and-run-fake-enclave.sh script (which sets them), the vsock
// abstraction (which reads them to emulate vsock over loopback TCP), and the
// E2E test harness. Keep these in sync with that script, which cannot import
// these constants.
const (
	// EnvEnclaveType selects the enclave environment; a value of
	// string(EnclaveTypeFake) ("FAKE") enables the fake environment.
	EnvEnclaveType = "ENCLAVE_TYPE"

	// EnvEnclaveCID is the vsock CID the enclave uses, which the fake vsock
	// backend maps to a stable loopback TCP port.
	EnvEnclaveCID = "ENCLAVE_CID"

	// EnvVSOCKBackend selects the vsock transport. A value of VSOCKBackendTCP
	// emulates vsock over loopback TCP for the fake environment.
	EnvVSOCKBackend = "VSOCK_BACKEND"

	// VSOCKBackendTCP is the EnvVSOCKBackend value that enables loopback-TCP
	// vsock emulation.
	VSOCKBackendTCP = "tcp"
)

type Enclave struct {
	EnclaveID         [32]byte    `json:"enclaveId"`
	EnclaveURL        string      `json:"enclaveURL"`
	TrustedValues     [][]byte    `json:"trustedValues"` // Array of trusted measurements the client accepts.
	EnclaveType       EnclaveType `json:"enclaveType"`
	EnclaveAuthHeader string      `json:"enclaveAuthHeader"`
	EnclaveExtraData  []byte      `json:"enclaveExtraData"`
	Region            string      `json:"region,omitempty"`
}

// RequirementsChecker reports whether an enclave satisfies a request's requirements.
type RequirementsChecker func(enclave Enclave) bool

type EnclavesList struct {
	Enclaves []Enclave
}

func (el *EnclavesList) Hash() [32]byte {
	h := sha256.New()

	h.Write([]byte(DomainSeparator))
	h.Write([]byte("\nEnclavesList\n"))

	writeLengthPrefix(h, len(el.Enclaves))
	for _, enclave := range el.Enclaves {
		h.Write(enclave.EnclaveID[:])
		writeWithLength(h, []byte(enclave.EnclaveURL))

		writeLengthPrefix(h, len(enclave.TrustedValues))
		for _, tv := range enclave.TrustedValues {
			writeWithLength(h, tv)
		}

		writeWithLength(h, []byte(enclave.EnclaveType))
		writeWithLength(h, []byte(enclave.EnclaveAuthHeader))
		writeWithLength(h, enclave.EnclaveExtraData)
		writeWithLength(h, []byte(enclave.Region))
	}

	var result [32]byte
	h.Sum(result[:0])
	return result
}

// ComputeRequest is the struct used to make requests to Confidential Compute capabilities.
//
// RequestID: a unique identifier for the request.
// ApplicationRequestID: application-specific request identity; for workflows this is the workflow execution ID.
// PublicData: non-sensitive data contained in the request. The marshalling format is up to the application.
// Ciphertexts: a list of the ciphertexts being requested for computation.
// CiphertextNames: the list of names of the ciphertexts being requested for computation.
// EncryptedDecryptionKeyShares: the encrypted shares produced by the threshold decryption process.
// EnclaveEphemeralPublicKey: the public key of the enclave selected to handle the request.
// MasterPublicKey: the threshold decryption public key that pertains to the request. It may act as an identifier of the current configuration.
// AppID: the identifier of the application making the request.
// Version: the version of the application making the request.
type ComputeRequest struct {
	RequestID                    [32]byte   `json:"requestID"`
	ApplicationRequestID         string     `json:"applicationRequestID"`
	PublicData                   []byte     `json:"publicData"`
	Ciphertexts                  [][]byte   `json:"ciphertexts"`
	CiphertextNames              []string   `json:"CiphertextNames"`
	EncryptedDecryptionKeyShares [][][]byte `json:"encryptedDecryptionKeyShares"`
	EnclaveEphemeralPublicKey    []byte     `json:"enclaveEphemeralPublicKey"`
	MasterPublicKey              []byte     `json:"masterPublicKey"`
	AppID                        string     `json:"appID"`
	Version                      string     `json:"version"`
}

func (cr *ComputeRequest) Hash() [32]byte {
	h := sha256.New()

	h.Write([]byte(DomainSeparator))
	h.Write([]byte("\nComputeRequest\n"))

	h.Write(cr.RequestID[:])

	// Length-prefixed fields
	writeWithLength(h, cr.PublicData)

	// Arrays with count + individual lengths
	writeLengthPrefix(h, len(cr.CiphertextNames))
	for _, name := range cr.CiphertextNames {
		writeWithLength(h, []byte(name))
	}

	writeLengthPrefix(h, len(cr.Ciphertexts))
	for _, ciphertext := range cr.Ciphertexts {
		writeWithLength(h, ciphertext)
	}

	writeWithLength(h, cr.EnclaveEphemeralPublicKey)
	writeWithLength(h, cr.MasterPublicKey)

	writeWithLength(h, []byte(cr.AppID))
	if cr.Version == ServiceConfidentialComputeVersionLegacy {
		writeWithLength(h, []byte(cr.Version))
	} else {
		writeWithLength(h, []byte(cr.ApplicationRequestID))
	}

	var result [32]byte
	h.Sum(result[:0])
	return result
}

func writeWithLength(h hash.Hash, data []byte) {
	writeLengthPrefix(h, len(data))
	h.Write(data)
}

func writeLengthPrefix(h hash.Hash, length int) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(length))
	h.Write(buf[:])
}

// SignedComputeRequest decorates the ComputeRequest struct with a signature.
type SignedComputeRequest struct {
	ComputeRequest
	Signature []byte `json:"signature"`
}

// MetricEvent is a single emitted observability event. Unlike the Metrics map
// (keyed by event name, so at most one entry per name survives), a slice of
// MetricEvents preserves every occurrence: a workflow that calls a capability N
// times yields N events, which the host re-emits as N counter increments plus N
// histogram samples. Carried outside the attestation; advisory telemetry only.
type MetricEvent struct {
	Event   string         `json:"event"`
	Details map[string]any `json:"details"`
}

type ExecuteResponse struct {
	RequestID            [32]byte      `json:"requestID"`
	ApplicationRequestID string        `json:"applicationRequestID"`
	RequestHash          [32]byte      `json:"requestHash"`
	Output               []byte        `json:"output"`
	Config               EnclaveConfig `json:"config"`
	Attestation          []byte        `json:"attestation"`
	// Metrics is the legacy name-keyed form, kept only so an old host can still
	// read metrics from a new enclave (and vice versa) during a rolling deploy.
	// It is a lossy projection of MetricEvents (dedup by event name, last wins).
	// TODO: this should be deprecated and removed once both the capability
	// (host/framework) and the enclave are on a version that speaks MetricEvents;
	// at that point stop populating it and drop the field. Not marked with the
	// magic "Deprecated:" prefix yet because it is still intentionally populated.
	Metrics map[string]any `json:"metrics,omitempty"`
	// MetricEvents is the ordered, duplicate-preserving form of Metrics. When
	// present the host re-emits from it instead of Metrics, so repeated per-call
	// events (e.g. capability_execution) count correctly. Additive for backward
	// compatibility with hosts/enclaves that only understand Metrics.
	MetricEvents []MetricEvent `json:"metricEvents,omitempty"`
	// AttestationFallbackUsed is set client-side when attestation validated against
	// previously trusted measurements instead of the current configured measurements.
	AttestationFallbackUsed bool `json:"-"`
}

// Error data must not contain sensitive information.
type ExecuteError struct {
	Error string
	Code  int
}

// EnclaveErrorResponse is the JSON structure returned by the enclave on error.
// It carries the error message and any metrics collected before the failure.
type EnclaveErrorResponse struct {
	Error string `json:"error"`
	// Metrics: see ExecuteResponse.Metrics. TODO: remove once host and enclave
	// both speak MetricEvents.
	Metrics map[string]any `json:"metrics,omitempty"`
	// MetricEvents mirrors ExecuteResponse.MetricEvents on the error path.
	MetricEvents []MetricEvent `json:"metricEvents,omitempty"`
}

func (er *ExecuteResponse) UserDataHash(requestVersion string) []byte {
	h := sha256.New()

	h.Write(er.RequestID[:])

	h.Write([]byte(DomainSeparator))
	h.Write([]byte("\nExecuteResponse\n"))

	// Variable-length output
	writeWithLength(h, er.Output)

	configHash := er.Config.Hash()
	h.Write(configHash[:])
	h.Write(er.RequestHash[:])
	if requestVersion != ServiceConfidentialComputeVersionLegacy {
		writeWithLength(h, []byte(er.ApplicationRequestID))
	}

	return h.Sum(nil)
}

type EnclavePublicKeyData struct {
	PublicKeyResponse
	EnclaveID [32]byte
	// AttestationFallbackUsed is set client-side when attestation validated against
	// previously trusted measurements instead of the current configured measurements.
	AttestationFallbackUsed bool `json:"-"`
}

type PublicKeyResponse struct {
	PublicKeys    [][]byte        `json:"publicKey"`
	CreationTimes []time.Time     `json:"creationTimes"`
	TTLs          []time.Duration `json:"ttls"`
	Config        EnclaveConfig   `json:"config"`
	Attestation   []byte          `json:"attestation"`
}

func (pkr *PublicKeyResponse) PublicKeyHash() [32]byte {
	h := sha256.New()

	// Domain Separator and Type Prefix
	h.Write([]byte(DomainSeparator))
	h.Write([]byte("\nPublicKeyResponse\n"))

	// PublicKeys (Array of slices, with count + length prefix for each key)
	writeLengthPrefix(h, len(pkr.PublicKeys))
	for _, publicKey := range pkr.PublicKeys {
		writeWithLength(h, publicKey)
	}

	// CreationTimes (Array of time.Time, hashed as BigEndian nanoseconds)
	writeLengthPrefix(h, len(pkr.CreationTimes))
	for _, creationTime := range pkr.CreationTimes {
		// Use nanoseconds since epoch (int64) for canonical encoding
		var timeBuf [8]byte
		nano := creationTime.UTC().UnixNano()
		binary.BigEndian.PutUint64(timeBuf[:], uint64(nano))
		h.Write(timeBuf[:])
	}

	// TTLs (Array of time.Duration, hashed as BigEndian nanoseconds)
	writeLengthPrefix(h, len(pkr.TTLs))
	for _, ttl := range pkr.TTLs {
		// time.Duration is int64 nanoseconds
		var ttlBuf [8]byte
		binary.BigEndian.PutUint64(ttlBuf[:], uint64(ttl))
		h.Write(ttlBuf[:])
	}

	// Config (Hash the EnclaveConfig's canonical hash)
	enclaveConfigHash := pkr.Config.Hash()
	h.Write(enclaveConfigHash[:]) // EnclaveConfig.Hash() already returns a fixed-size [32]byte hash

	var result [32]byte
	h.Sum(result[:0])
	return result
}

type EnclaveConfig struct {
	Signers         [][]byte `json:"signers"`
	MasterPublicKey []byte   `json:"masterPublicKey"`
	T               uint32   `json:"t"`
	F               uint32   `json:"f"`
}

func (ec *EnclaveConfig) IsZero() bool {
	if ec == nil {
		return true
	}
	return ec.T == 0 && ec.F == 0 && len(ec.Signers) == 0 && len(ec.MasterPublicKey) == 0
}

func (ec *EnclaveConfig) Hash() [32]byte {
	h := sha256.New()

	// Domain Separator and Type Prefix
	h.Write([]byte(DomainSeparator))
	h.Write([]byte("\nEnclaveConfig\n"))

	// Signers (Array with count + individual lengths using writeWithLength)
	writeLengthPrefix(h, len(ec.Signers))
	for _, signer := range ec.Signers {
		// Each signer is a []byte and is written with its length prefix
		writeWithLength(h, signer)
	}

	// MasterPublicKey (Slice with its length prefix)
	writeWithLength(h, ec.MasterPublicKey)

	// T (Fixed size, but must be BigEndian for consistency with writeLengthPrefix, 4 bytes)
	var tBuf [4]byte
	binary.BigEndian.PutUint32(tBuf[:], ec.T)
	h.Write(tBuf[:])

	// F (Fixed size, but must be BigEndian for consistency with writeLengthPrefix, 4 bytes)
	var fBuf [4]byte
	binary.BigEndian.PutUint32(fBuf[:], ec.F)
	h.Write(fBuf[:])

	var result [32]byte
	h.Sum(result[:0])
	return result
}

func (ec *EnclaveConfig) Copy() EnclaveConfig {
	if ec == nil {
		return EnclaveConfig{}
	}
	copied := EnclaveConfig{
		MasterPublicKey: make([]byte, len(ec.MasterPublicKey)),
		T:               ec.T,
		F:               ec.F,
	}
	copy(copied.MasterPublicKey, ec.MasterPublicKey)
	copied.Signers = make([][]byte, len(ec.Signers))
	for i, signer := range ec.Signers {
		copied.Signers[i] = make([]byte, len(signer))
		copy(copied.Signers[i], signer)
	}
	return copied
}

type ConfigRequest struct {
	Config []byte `json:"config"`
}

type SetConfigResponse struct {
	Config      EnclaveConfig `json:"config"`
	Attestation []byte        `json:"attestation"`
}

type UpdateConfigRequest struct {
	Config    []byte `json:"config"`    // JSON-marshaled EnclaveConfig being proposed
	Signature []byte `json:"signature"` // signature over the proposed config's domain-separated hash
}

type UpdateConfigResponse struct {
	Applied          bool          `json:"applied"`
	Config           EnclaveConfig `json:"config"`
	SignersCollected int           `json:"signersCollected"`
	SignersRequired  int           `json:"signersRequired"`
	Attestation      []byte        `json:"attestation,omitempty"` // set, over Config, only when Applied
}

func (sr *SetConfigResponse) UserDataHash() []byte {
	var data []byte
	data = append(data, []byte(DomainSeparator)...)
	data = append(data, []byte("\nSetConfigResponse\n")...)
	enclaveConfigHash := sr.Config.Hash()
	data = append(data, enclaveConfigHash[:]...)
	hash := sha256.Sum256(data)
	return hash[:]
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// The emitter allows for an enclave to emit structured events to the host application.
// All work done in the emitter should be assumed to be in plaintext,
// and any data passed to the emitter should be nonsensitive.
type Emitter interface {
	Emit(event string, details map[string]any)
}

type EnclaveApp interface {
	// rawSignedRequests is the signed compute-request batch this execution came from;
	// confidential-workflows forwards it to the relay DON for authorization, other apps ignore it.
	Execute(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter Emitter, rawSignedRequests ...SignedComputeRequest) ([]byte, *ExecuteError)
}

type MemoryEstimateResponse struct {
	// UsedMB is all memory mapped by the Go runtime, rounded to the nearest
	// megabyte.
	UsedMB uint64 `json:"usedMB"`
}
