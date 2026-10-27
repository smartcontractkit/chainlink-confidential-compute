package app

import (
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelaySecretsCallbackID(t *testing.T) {
	base := confidentialrelay.SecretsRequestParams{
		WorkflowID:       "wf-secrets",
		Owner:            "0x0123456789AbcdEF0123456789aBcdef01234567",
		ExecutionID:      strings.Repeat("a", 64),
		Secrets:          []confidentialrelay.SecretIdentifier{{Key: "API_KEY", Namespace: "main"}},
		EnclavePublicKey: "aa",
		EnclaveConfig: &confidentialrelay.EnclaveConfig{
			Signers:         [][]byte{[]byte("signer")},
			MasterPublicKey: []byte("master-public-key"),
			T:               1,
			F:               1,
		},
	}
	derive := func(t *testing.T, p confidentialrelay.SecretsRequestParams) int32 {
		t.Helper()
		id, err := relaySecretsCallbackID(p)
		require.NoError(t, err)
		return id
	}

	baseID := derive(t, base)
	assert.Negative(t, baseID, "a guest callback ID of 0 must still derive a nonzero ID")
	assert.Equal(t, baseID, derive(t, base))

	authorization := base
	authorization.Attestation = "attestation"
	authorization.SignedComputeRequests = []confidentialrelay.SignedComputeRequest{{Signature: []byte("signature")}}
	assert.Equal(t, baseID, derive(t, authorization), "authorization input must not change the ID")

	for name, mutate := range map[string]func(p *confidentialrelay.SecretsRequestParams){
		"enclave key": func(p *confidentialrelay.SecretsRequestParams) { p.EnclavePublicKey = "bb" },
		"enclave config": func(p *confidentialrelay.SecretsRequestParams) {
			p.EnclaveConfig = &confidentialrelay.EnclaveConfig{
				Signers:         [][]byte{[]byte("signer")},
				MasterPublicKey: []byte("reshared-master-public-key"),
				T:               1,
				F:               1,
			}
		},
		"secrets": func(p *confidentialrelay.SecretsRequestParams) {
			p.Secrets = []confidentialrelay.SecretIdentifier{{Key: "OTHER_KEY", Namespace: "main"}}
		},
		"guest callback ID": func(p *confidentialrelay.SecretsRequestParams) { p.CallbackID = 1 },
		"execution":         func(p *confidentialrelay.SecretsRequestParams) { p.ExecutionID = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			id := derive(t, p)
			assert.Negative(t, id)
			assert.NotEqual(t, baseID, id)
		})
	}
}
