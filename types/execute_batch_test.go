package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBatch(t *testing.T) ExecuteBatch {
	t.Helper()
	return ExecuteBatch{
		Requests: []SignedComputeRequest{
			{
				ComputeRequest: ComputeRequest{
					RequestID:  [32]byte{1, 2, 3},
					AppID:      AppIDConfidentialWorkflows,
					PublicData: []byte("public"),
				},
				Signature: []byte("sig-a"),
			},
			{
				ComputeRequest: ComputeRequest{
					RequestID:  [32]byte{1, 2, 3},
					AppID:      AppIDConfidentialWorkflows,
					PublicData: []byte("public"),
				},
				Signature: []byte("sig-b"),
			},
		},
		UnauthenticatedData: []byte("wasm-bytes"),
	}
}

func TestExecuteBatch_RoundTrip(t *testing.T) {
	want := testBatch(t)
	body, err := MarshalExecuteBatch(want)
	require.NoError(t, err)

	got, err := UnmarshalExecuteBatch(body)
	require.NoError(t, err)
	assert.Equal(t, want.Requests, got.Requests)
	assert.Equal(t, want.UnauthenticatedData, got.UnauthenticatedData)
}

// A new enclave must still understand the bare array an old host sends, since
// the host and enclave images roll independently.
func TestUnmarshalExecuteBatch_AcceptsLegacyArray(t *testing.T) {
	reqs := testBatch(t).Requests
	body, err := json.Marshal(reqs)
	require.NoError(t, err)

	got, err := UnmarshalExecuteBatch(body)
	require.NoError(t, err)
	assert.Equal(t, reqs, got.Requests)
	assert.Empty(t, got.UnauthenticatedData, "a legacy host supplies no data")
}

func TestUnmarshalExecuteBatch_AcceptsLeadingWhitespace(t *testing.T) {
	reqs := testBatch(t).Requests
	body, err := json.Marshal(reqs)
	require.NoError(t, err)

	got, err := UnmarshalExecuteBatch(append([]byte("\n\t "), body...))
	require.NoError(t, err)
	assert.Len(t, got.Requests, len(reqs))
}

func TestUnmarshalExecuteBatch_OmitsEmptyUnauthenticatedData(t *testing.T) {
	batch := testBatch(t)
	batch.UnauthenticatedData = nil
	body, err := MarshalExecuteBatch(batch)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "unauthenticatedData", "an absent field should not bloat the vsock payload")
}

func TestUnmarshalExecuteBatch_Invalid(t *testing.T) {
	for name, body := range map[string]string{
		"garbage":    "not json",
		"bad array":  `[{"requestID": 5}]`,
		"bad object": `{"requests": "nope"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalExecuteBatch([]byte(body))
			assert.Error(t, err)
		})
	}
}
