package attestationvalidator

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// coseSign1 mirrors the COSE_Sign1 array structure wrapping a Nitro attestation.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"` //nolint:revive // idiomatic CBOR array encoding
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// attestationPayload holds the Nitro attestation payload fields used for diagnostics.
type attestationPayload struct {
	ModuleID string          `cbor:"module_id"`
	PCRs     map[uint][]byte `cbor:"pcrs"`
}

// DescribeMeasurements decodes the PCR measurements a Nitro attestation actually
// reports, for diagnostic logging when validation fails. It does NOT verify the
// signature or certificate chain; it only parses the COSE_Sign1 payload so the
// measurements the enclave reported can be compared against the expected trusted
// values. Returns a short summary, or a note when the document cannot be parsed
// (e.g. a fake attestation).
func DescribeMeasurements(attestation []byte) string {
	if len(attestation) == 0 {
		return "no attestation received"
	}
	var sign1 coseSign1
	if err := cbor.Unmarshal(attestation, &sign1); err != nil || len(sign1.Payload) == 0 {
		return "unparseable attestation (not a Nitro COSE document)"
	}
	var payload attestationPayload
	if err := cbor.Unmarshal(sign1.Payload, &payload); err != nil {
		return "unparseable attestation payload"
	}
	return fmt.Sprintf("moduleID=%s PCR0=%x PCR1=%x PCR2=%x",
		payload.ModuleID, payload.PCRs[0], payload.PCRs[1], payload.PCRs[2])
}
