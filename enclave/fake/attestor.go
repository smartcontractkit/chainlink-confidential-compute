package fake

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// FakeAttestor is a dummy attestor for the fake enclave environment.
type FakeAttestor struct{}

// CreateAttestation returns a hardcoded mock attestation.
func (f *FakeAttestor) CreateAttestation(data []byte) ([]byte, error) {
	return []byte(types.FakeAttestationDocument), nil
}

// ValidateAttestation accepts the canonical fake attestation document produced
// by FakeAttestor and rejects anything else. It mirrors nitro.ValidateAttestation
// so the client can select it by enclave type. Measurements are intentionally
// ignored: the fake enclave environment produces no real measurements to verify.
func ValidateAttestation(attestation, _, _ []byte) error {
	if string(attestation) == types.FakeAttestationDocument {
		return nil
	}
	return fmt.Errorf("invalid fake attestation")
}
