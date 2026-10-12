package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetSecrets_ResharePublicKeyFromResponse is the confidential-workflows analog
// of TestConfidentialHttpEnclave_ResharePublicKeyFromRequest: it exercises the
// runtime getSecret (relay) path, asserting the enclave aggregates decryption
// shares with the vault public key carried in the relay response
// (SecretsResponseResult.RawVaultPublicKey) rather than its configured
// MasterPublicKey. That keeps runtime secret reads correct across DKG reshares,
// where the configured key can be stale relative to the shares the vault DON just
// produced.
func TestGetSecrets_ResharePublicKeyFromResponse(t *testing.T) {
	staleConfiguredKey := []byte("stale-configured-master-public-key")
	liveResponseKey := []byte("live-dkg-master-public-key-from-response")
	liveResponseKeyHex := hex.EncodeToString(liveResponseKey)

	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	plaintext := "the-secret-value"

	// Build a relay response result for the given params; the gateway handler signs
	// it with the request's params so the dispatcher's quorum/signature check passes.
	newResult := func(rawVaultPublicKey string) confidentialrelay.SecretsResponseResult {
		return confidentialrelay.SecretsResponseResult{
			RawVaultPublicKey: rawVaultPublicKey,
			Secrets: []confidentialrelay.SecretEntry{{
				ID:         secretID,
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
				// No encrypted shares: the combiner is stubbed, so share decryption
				// via the keypair is not exercised; we only assert the master key the
				// dispatcher selects for aggregation.
				EncryptedShares: nil,
			}},
		}
	}

	run := func(t *testing.T, rawVaultPublicKey string) (gotMasterPK []byte, value string) {
		t.Helper()
		signers := newRelaySigners(t, 2)

		comb := &stubCombiner{aggregateFn: func(_ []byte, _ [][]byte, publicKey []byte, _ int) ([]byte, error) {
			gotMasterPK = publicKey
			return []byte(plaintext), nil
		}}

		srv := httptest.NewServer(jsonRPCHandler(t, func(method string, params json.RawMessage) (any, error) {
			require.Equal(t, confidentialrelay.MethodSecretsGet, method)
			var p confidentialrelay.SecretsRequestParams
			require.NoError(t, json.Unmarshal(params, &p))
			return signSecretsBundle(t, newResult(rawVaultPublicKey), p, signers), nil
		}))
		defer srv.Close()

		cfg := relayDONConfig(signers, 1)
		cfg.MasterPublicKey = staleConfiguredKey // stale, as after a reshare

		d := NewRemoteDispatcher(
			gateway.NewGatewayClient(srv.URL, nil),
			nil, // attestor (nil => empty attestation)
			cfg,
			logger.Test(t),
			&stubKeychain{kp: &stubKeypair{pub: []byte("enclave-ephemeral-pub")}},
			comb,
			signatureverifier.NewEd25519SignatureVerifier(),
			0, 0,
		)

		resp, err := d.GetSecrets(
			context.Background(),
			"wf-secrets",
			[32]byte{1},
			&sdkpb.GetSecretsRequest{Requests: []*sdkpb.SecretRequest{{Id: secretID.Key, Namespace: secretID.Namespace}}},
			"0x0123456789abcdef0123456789abcdef01234567",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"",
			nil,
		)
		require.NoError(t, err)
		require.Len(t, resp, 1)
		return gotMasterPK, resp[0].GetSecret().GetValue()
	}

	t.Run("prefers response key over stale configured key", func(t *testing.T) {
		gotMasterPK, value := run(t, liveResponseKeyHex)
		assert.Equal(t, plaintext, value)
		assert.Equal(t, liveResponseKey, gotMasterPK, "must aggregate with the relay-forwarded key")
		assert.NotEqual(t, staleConfiguredKey, gotMasterPK, "must not use the stale configured key")
	})

	t.Run("falls back to configured key when response omits it", func(t *testing.T) {
		gotMasterPK, value := run(t, "")
		assert.Equal(t, plaintext, value)
		assert.Equal(t, staleConfiguredKey, gotMasterPK, "with no response key, aggregate with the configured key")
	})
}

// --- stubs ---

type stubCombiner struct {
	aggregateFn func(ciphertext []byte, shares [][]byte, publicKey []byte, threshold int) ([]byte, error)
}

func (s *stubCombiner) AggregateShares(ciphertext []byte, shares [][]byte, publicKey []byte, threshold int) ([]byte, error) {
	return s.aggregateFn(ciphertext, shares, publicKey, threshold)
}

func (s *stubCombiner) VerifyShare(_ []byte, _ []byte, _ []byte) error { return nil }

type stubKeypair struct{ pub []byte }

func (k *stubKeypair) Public() []byte                   { return k.pub }
func (k *stubKeypair) Decrypt(b []byte) ([]byte, error) { return b, nil }
func (k *stubKeypair) TTL() time.Duration               { return time.Hour }
func (k *stubKeypair) CreationTime() time.Time          { return time.Time{} }

type stubKeychain struct{ kp keychain.Keypair }

func (s *stubKeychain) CreateKeyPair() (keychain.Keypair, error)      { return s.kp, nil }
func (s *stubKeychain) GetKeyPair([]byte) (keychain.Keypair, error)   { return s.kp, nil }
func (s *stubKeychain) GetKeyPairs() ([]keychain.Keypair, error)      { return []keychain.Keypair{s.kp}, nil }
func (s *stubKeychain) GetKeyPairForRequest([32]byte) (keychain.Keypair, error) {
	return s.kp, nil
}
func (s *stubKeychain) DeleteKeyPair([]byte) error { return nil }

// signSecretsBundle signs the given secrets result with each relay signer over
// result.Hash(params), mirroring the honest relay flow (see signCapabilityBundle).
func signSecretsBundle(
	t *testing.T,
	result confidentialrelay.SecretsResponseResult,
	params confidentialrelay.SecretsRequestParams,
	signers []relaySigner,
) confidentialrelay.SignedSecretsResponseBundle {
	t.Helper()
	hash, err := result.Hash(params)
	require.NoError(t, err)
	resps := make([]confidentialrelay.SignedSecretsResponseResult, len(signers))
	for i, s := range signers {
		resps[i] = confidentialrelay.SignedSecretsResponseResult{Result: result, Signature: s.sign(hash)}
	}
	return confidentialrelay.SignedSecretsResponseBundle{Responses: resps}
}
