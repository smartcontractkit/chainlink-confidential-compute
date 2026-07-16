package types

import (
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
