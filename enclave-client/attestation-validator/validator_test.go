package attestationvalidator

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// passthroughMeter counts additions to the passthrough validation counter.
type passthroughMeter struct {
	noop.Meter
	count atomic.Int64
}

func (m *passthroughMeter) Int64Counter(name string, _ ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if name != "teeattestation_passthrough_validation_count" {
		return noop.Int64Counter{}, nil
	}
	return passthroughCounter{meter: m}, nil
}

type passthroughCounter struct {
	noop.Int64Counter
	meter *passthroughMeter
}

func (c passthroughCounter) Add(_ context.Context, incr int64, _ ...metric.AddOption) {
	c.meter.count.Add(incr)
}

var meter = &passthroughMeter{}

// TestMain installs the counting meter before any validation runs, because the
// fake validator registers its counter once per process.
func TestMain(m *testing.M) {
	client := beholder.NewNoopClient()
	client.Meter = meter
	beholder.SetClient(client)
	os.Exit(m.Run())
}

// Only EnclaveTypeFake may select the passthrough validator; any other value
// from the registry, including near-miss spellings, must get Nitro validation.
func TestForEnclaveType(t *testing.T) {
	fakeDoc := []byte(types.FakeAttestationDocument)
	for _, enclaveType := range []types.EnclaveType{
		types.EnclaveTypeNitro, types.EnclaveTypeSGX, types.EnclaveTypeTDX, types.EnclaveTypeSEV,
		"", "fake", "Fake", " FAKE", "FAKE ", "nitro",
	} {
		t.Run(string(enclaveType), func(t *testing.T) {
			v := ForEnclaveType(enclaveType, nil)
			assert.IsType(t, nitroValidator{}, v)
			require.Error(t, v.ValidateAttestation(fakeDoc, nil, nil))
		})
	}

	v := ForEnclaveType(types.EnclaveTypeFake, nil)
	assert.IsType(t, fakeValidator{}, v)
	require.NoError(t, v.ValidateAttestation(fakeDoc, nil, nil))
	require.Error(t, v.ValidateAttestation([]byte("not-the-fake-document"), nil, nil))
}

func TestFakeValidatorRecordsPassthroughValidation(t *testing.T) {
	v := ForEnclaveType(types.EnclaveTypeFake, nil)
	before := meter.count.Load()

	require.NoError(t, v.ValidateAttestation([]byte(types.FakeAttestationDocument), nil, nil))
	require.NoError(t, v.ValidateAttestationWithRoots([]byte(types.FakeAttestationDocument), nil, nil, "ignored"))

	assert.Equal(t, before+2, meter.count.Load())
}

// DescribeMeasurements parses attestations from failing enclaves for logging,
// so malformed input must produce a summary rather than a panic.
func TestDescribeMeasurements(t *testing.T) {
	payload, err := cbor.Marshal(attestationPayload{
		ModuleID: "i-0123",
		PCRs:     map[uint][]byte{0: {0xaa}, 1: {0xbb}, 2: {0xcc}},
	})
	require.NoError(t, err)
	doc, err := cbor.Marshal(coseSign1{
		Protected:   []byte{0xa0},
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   []byte("signature"),
	})
	require.NoError(t, err)
	badPayloadDoc, err := cbor.Marshal(coseSign1{
		Protected:   []byte{0xa0},
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     []byte{0xff},
		Signature:   []byte("signature"),
	})
	require.NoError(t, err)

	assert.Equal(t, "moduleID=i-0123 PCR0=aa PCR1=bb PCR2=cc", DescribeMeasurements(doc))
	assert.Equal(t, "no attestation received", DescribeMeasurements(nil))
	assert.Equal(t, "unparseable attestation (not a Nitro COSE document)", DescribeMeasurements([]byte(types.FakeAttestationDocument)))
	assert.Equal(t, "unparseable attestation payload", DescribeMeasurements(badPayloadDoc))

	for n := 1; n < len(doc); n++ {
		assert.NotPanics(t, func() { DescribeMeasurements(doc[:n]) }, "truncated to %d bytes", n)
	}
}
