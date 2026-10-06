package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func sampleComputeRequest() ComputeRequest {
	var rid [32]byte
	for i := range rid {
		rid[i] = byte(i)
	}
	return ComputeRequest{
		RequestID:                 rid,
		ApplicationRequestID:      "application-request-id",
		PublicData:                []byte("public-data"),
		Ciphertexts:               [][]byte{[]byte("ct-a"), []byte("ct-b")},
		CiphertextNames:           []string{"name-a", "name-b"},
		EnclaveEphemeralPublicKey: []byte("ephemeral-pub-key"),
		MasterPublicKey:           []byte("master-pub-key"),
		AppID:                     "test-app",
		Version:                   ServiceConfidentialComputeVersionLegacy,
	}
}

func TestComputeRequestHash_ApplicationRequestIDOnlyHashedForNonLegacy(t *testing.T) {
	legacyA := sampleComputeRequest()
	legacyA.ApplicationRequestID = "exec-a"
	legacyB := sampleComputeRequest()
	legacyB.ApplicationRequestID = "exec-b"
	require.Equal(t, legacyA.Hash(), legacyB.Hash(), "legacy ApplicationRequestID must not affect the hash")

	nonLegacyA := sampleComputeRequest()
	nonLegacyA.Version = "0.0.7"
	nonLegacyA.ApplicationRequestID = "exec-a"
	nonLegacyB := sampleComputeRequest()
	nonLegacyB.Version = "0.0.7"
	nonLegacyB.ApplicationRequestID = "exec-b"
	require.NotEqual(t, nonLegacyA.Hash(), nonLegacyB.Hash(), "non-legacy ApplicationRequestID must be bound into the hash")
}

func TestComputeRequestHash_VersionOnlyHashedForLegacy(t *testing.T) {
	nonLegacyA := sampleComputeRequest()
	nonLegacyA.Version = "0.0.7"
	nonLegacyB := sampleComputeRequest()
	nonLegacyB.Version = "1.2.3"
	require.Equal(t, nonLegacyA.Hash(), nonLegacyB.Hash(), "non-legacy Version must not affect the hash")

	legacy := sampleComputeRequest()
	legacy.Version = ServiceConfidentialComputeVersionLegacy
	require.NotEqual(t, legacy.Hash(), nonLegacyA.Hash(), "legacy Version must be bound into the hash")
}

func TestComputeRequestHash_IgnoresEncryptedShares(t *testing.T) {
	base := sampleComputeRequest()
	withShares := sampleComputeRequest()
	withShares.EncryptedDecryptionKeyShares = [][][]byte{{[]byte("share")}}
	require.Equal(t, base.Hash(), withShares.Hash())
}

func sampleExecuteResponse() ExecuteResponse {
	return ExecuteResponse{
		RequestID:            [32]byte{1, 2, 3},
		ApplicationRequestID: "application-request-id",
		RequestHash:          [32]byte{4, 5, 6},
		Output:               []byte("output"),
		Config: EnclaveConfig{
			Signers:         [][]byte{[]byte("signer-a")},
			MasterPublicKey: []byte("master-public-key"),
			T:               1,
			F:               0,
		},
	}
}

func TestExecuteResponseUserDataHash_ApplicationRequestIDOnlyHashedForNonLegacy(t *testing.T) {
	legacyA := sampleExecuteResponse()
	legacyA.ApplicationRequestID = "exec-a"
	legacyB := sampleExecuteResponse()
	legacyB.ApplicationRequestID = "exec-b"
	require.Equal(t,
		legacyA.UserDataHash(ServiceConfidentialComputeVersionLegacy),
		legacyB.UserDataHash(ServiceConfidentialComputeVersionLegacy),
		"legacy ApplicationRequestID must not affect the response hash",
	)

	nonLegacyA := sampleExecuteResponse()
	nonLegacyA.ApplicationRequestID = "exec-a"
	nonLegacyB := sampleExecuteResponse()
	nonLegacyB.ApplicationRequestID = "exec-b"
	require.NotEqual(t,
		nonLegacyA.UserDataHash("0.0.7"),
		nonLegacyB.UserDataHash("0.0.7"),
		"non-legacy ApplicationRequestID must be bound into the response hash",
	)
}

// Config-update votes are signed over EnclaveConfig.Hash and set-config
// attestations bind UserDataHash, so a format change breaks verification
// between enclave and capability versions.
func TestEnclaveConfigHash_Golden(t *testing.T) {
	cfg := EnclaveConfig{
		Signers:         [][]byte{[]byte("signer-a"), []byte("signer-b")},
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               1,
	}
	h := cfg.Hash()
	require.Equal(t, "00af21b6cae2042d2c8804f8fcc9a4831d6359a896a5c03ffb0046533ba63892", hex.EncodeToString(h[:]))

	resp := SetConfigResponse{Config: cfg}
	require.Equal(t, "b4518a5ab5b47c3b3a016b5d04f9094708e4e406b45b5741b9e325be095e1971", hex.EncodeToString(resp.UserDataHash()))
}

// Peer-ID signatures are verified by other nodes, so the payload format is
// pinned for both the inline (<= 1024 bytes) and hashed message branches.
func TestMakePeerIDSignatureDomainSeparatedPayload_Golden(t *testing.T) {
	short := sha256.Sum256(MakePeerIDSignatureDomainSeparatedPayload("domain", []byte("message")))
	require.Equal(t, "c8659d590c4fdabe8ec173088b072c932de10cf904681950a57ed72331e6a51c", hex.EncodeToString(short[:]))

	long := sha256.Sum256(MakePeerIDSignatureDomainSeparatedPayload("domain", bytes.Repeat([]byte("m"), 2048)))
	require.Equal(t, "dd7197e44494a073a2b6e588223d66ac5e91eda819b23817db4ec69524071eaf", hex.EncodeToString(long[:]))
}
