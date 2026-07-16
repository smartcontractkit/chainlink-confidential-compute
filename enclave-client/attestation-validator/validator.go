// This package provides the `AttestationValidator` interface for validating TEE
// attestation documents. It also provides implementations for each enclave
// type: the production Nitro validator and the fake passthrough validator.

package attestationvalidator

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/teeattestation/nitro"

	"github.com/smartcontractkit/confidential-compute/enclave/fake"
	"github.com/smartcontractkit/confidential-compute/types"
)

// AttestationValidator validates TEE attestation documents, with or without a
// custom CA root. Both the production Nitro validator and the fake passthrough
// validator implement it, so callers validate the same way regardless of which
// enclave type produced the attestation.
type AttestationValidator interface {
	ValidateAttestation(attestation, expectedUserData, trustedMeasurements []byte) error
	ValidateAttestationWithRoots(attestation, expectedUserData, trustedMeasurements []byte, caRootsPEM string) error
}

var (
	_ AttestationValidator = nitroValidator{}
	_ AttestationValidator = fakeValidator{}
)

// nitroValidator is the production validator backed by AWS Nitro.
type nitroValidator struct{}

func (nitroValidator) ValidateAttestation(attestation, expectedUserData, trustedMeasurements []byte) error {
	return nitro.ValidateAttestation(attestation, expectedUserData, trustedMeasurements)
}

func (nitroValidator) ValidateAttestationWithRoots(attestation, expectedUserData, trustedMeasurements []byte, caRootsPEM string) error {
	return nitro.ValidateAttestationWithRoots(attestation, expectedUserData, trustedMeasurements, caRootsPEM)
}

// fakeValidationCounter counts every use of the fake validator. It reuses the
// chainlink-common passthrough validator's metric name so the insecure,
// non-Nitro validation path can be alerted on if it is ever exercised outside
// tests. The fake validator is selected per call in a loop, so the counter is
// registered once lazily and shared.
var (
	fakeValidationCounter     metric.Int64Counter
	fakeValidationCounterOnce sync.Once
)

func recordFakeValidation(lggr types.Logger) {
	fakeValidationCounterOnce.Do(func() {
		var err error
		fakeValidationCounter, err = beholder.GetMeter().Int64Counter("teeattestation_passthrough_validation_count")
		if err != nil && lggr != nil {
			lggr.Warnw("failed to register fake attestation validation metric; insecure path will be unobservable", "error", err)
		}
	})
	if fakeValidationCounter != nil {
		fakeValidationCounter.Add(context.Background(), 1)
	}
}

// fakeValidator accepts the canonical fake attestation document and rejects
// anything else. Measurements and CA roots are intentionally ignored: the fake
// enclave environment produces no real measurements to verify. Every use is
// recorded via recordFakeValidation so the insecure path stays observable.
type fakeValidator struct {
	lggr types.Logger
}

func (v fakeValidator) ValidateAttestation(attestation, expectedUserData, trustedMeasurements []byte) error {
	recordFakeValidation(v.lggr)
	return fake.ValidateAttestation(attestation, expectedUserData, trustedMeasurements)
}

func (v fakeValidator) ValidateAttestationWithRoots(attestation, expectedUserData, trustedMeasurements []byte, _ string) error {
	return v.ValidateAttestation(attestation, expectedUserData, trustedMeasurements)
}

// NewAttestationValidator returns the production validator backed by AWS Nitro.
func NewAttestationValidator() AttestationValidator {
	return nitroValidator{}
}

// ForEnclaveType returns the validator appropriate for the given enclave type.
// Fake enclaves use the fake validator; everything else uses the real Nitro
// attestation validator. The logger is used by the fake validator to warn if its
// observability metric fails to register.
func ForEnclaveType(enclaveType types.EnclaveType, lggr types.Logger) AttestationValidator {
	switch enclaveType {
	case types.EnclaveTypeFake:
		return fakeValidator{lggr: lggr}
	default:
		return nitroValidator{}
	}
}
