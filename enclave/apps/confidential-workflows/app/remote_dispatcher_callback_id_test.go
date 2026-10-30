package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/teeattestation"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoAttestor returns the attested data as the attestation document, so a relay
// fake can check what the dispatcher attested.
type echoAttestor struct{}

func (echoAttestor) CreateAttestation(data []byte) ([]byte, error) { return data, nil }

// TestGetSecrets_RetryOnNewEnclaveKeyFetchesFreshResult reproduces INCIDENT-2692
// against a relay that memoizes signed secrets results by (workflow, execution,
// callback ID), as chainlink's confidentialrelay secretsKey does. A re-run of the
// same WASM call on an enclave with a different key must get a result signed for
// its own request, while a retry with the same key is still served from the memo.
// The fake also checks the attestation covers the params as sent, as the relay
// does, so the derived ID must be set before attesting.
func TestGetSecrets_RetryOnNewEnclaveKeyFetchesFreshResult(t *testing.T) {
	signers := newRelaySigners(t, 2)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	result := confidentialrelay.SecretsResponseResult{
		Secrets: []confidentialrelay.SecretEntry{{
			ID:         secretID,
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		}},
	}

	memo := map[string]confidentialrelay.SignedSecretsResponseBundle{}
	fetches := 0
	srv := httptest.NewServer(jsonRPCHandler(t, func(method string, raw json.RawMessage) (any, error) {
		require.Equal(t, confidentialrelay.MethodSecretsGet, method)
		var p confidentialrelay.SecretsRequestParams
		require.NoError(t, json.Unmarshal(raw, &p))
		attested, err := base64.StdEncoding.DecodeString(p.Attestation)
		require.NoError(t, err)
		unattested := p
		unattested.Attestation = ""
		unattestedJSON, err := json.Marshal(unattested)
		require.NoError(t, err)
		if !assert.Equal(t, teeattestation.DomainHash(confidentialrelay.DomainSecretsGet, unattestedJSON), attested,
			"the attestation must cover the params as sent") {
			return nil, fmt.Errorf("attestation does not cover the params as sent")
		}
		key := fmt.Sprintf("%s/%s/%d", p.WorkflowID, p.ExecutionID, p.CallbackID)
		if bundle, ok := memo[key]; ok {
			return bundle, nil
		}
		fetches++
		memo[key] = signSecretsBundle(t, result, p, signers)
		return memo[key], nil
	}))
	defer srv.Close()

	getSecret := func(t *testing.T, enclaveKey string) {
		t.Helper()
		d := NewRemoteDispatcher(
			gateway.NewGatewayClient(srv.URL, nil),
			echoAttestor{},
			relayDONConfig(signers, 1),
			logger.Test(t),
			&stubKeychain{kp: &stubKeypair{pub: []byte(enclaveKey)}},
			&stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) { return []byte("value"), nil }},
			signatureverifier.NewEd25519SignatureVerifier(),
			0, 0,
		)
		resp, err := d.GetSecrets(
			context.Background(),
			"wf-secrets",
			[32]byte{1},
			&sdkpb.GetSecretsRequest{
				CallbackId: 0,
				Requests:   []*sdkpb.SecretRequest{{Id: secretID.Key, Namespace: secretID.Namespace}},
			},
			"0x0123456789abcdef0123456789abcdef01234567",
			strings.Repeat("a", 64),
			"",
			nil,
		)
		require.NoError(t, err)
		require.Len(t, resp, 1)
		assert.Equal(t, "value", resp[0].GetSecret().GetValue())
	}

	getSecret(t, "enclave-1-key")
	getSecret(t, "enclave-1-key")
	assert.Equal(t, 1, fetches, "a retry with the same enclave key is served from the relay memo")

	getSecret(t, "enclave-2-key")
	assert.Equal(t, 2, fetches, "a retry on a new enclave key fetches a result for its own request")
}

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
