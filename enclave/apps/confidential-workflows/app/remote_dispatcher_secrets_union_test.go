package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// signSecretsBundleVaried has each signer sign its own result over the same
// request params, as when relay nodes return different share sets.
func signSecretsBundleVaried(
	t *testing.T,
	results []confidentialrelay.SecretsResponseResult,
	params confidentialrelay.SecretsRequestParams,
	signers []relaySigner,
) confidentialrelay.SignedSecretsResponseBundle {
	t.Helper()
	require.Len(t, results, len(signers))
	resps := make([]confidentialrelay.SignedSecretsResponseResult, len(signers))
	for i, signer := range signers {
		hash, err := results[i].Hash(params)
		require.NoError(t, err)
		resps[i] = confidentialrelay.SignedSecretsResponseResult{
			Result:    results[i],
			Signature: signer.sign(hash),
		}
	}
	return confidentialrelay.SignedSecretsResponseBundle{Responses: resps}
}

func runSecretsDispatcher(
	t *testing.T,
	signers []relaySigner,
	f uint32,
	comb *stubCombiner,
	resultsFor func(params confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult,
) ([]*sdkpb.SecretResponse, error) {
	t.Helper()
	return runSecretsDispatcherFor(t, signers, f, comb, &stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: "API_KEY", Namespace: "main"}}, resultsFor)
}

func runSecretsDispatcherFor(
	t *testing.T,
	signers []relaySigner,
	f uint32,
	comb combiner.Combiner,
	kp keychain.Keypair,
	requests []*sdkpb.SecretRequest,
	resultsFor func(params confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult,
) ([]*sdkpb.SecretResponse, error) {
	t.Helper()
	cfg := relayDONConfig(signers, f)
	cfg.MasterPublicKey = []byte("configured-master-public-key")
	return runSecretsDispatcherWithConfig(t, signers, cfg, comb, kp, requests, 0, resultsFor)
}

func runSecretsDispatcherWithConfig(
	t *testing.T,
	signers []relaySigner,
	cfg types.EnclaveConfig,
	comb combiner.Combiner,
	kp keychain.Keypair,
	requests []*sdkpb.SecretRequest,
	maxSharesPerSigner int64,
	resultsFor func(params confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult,
) ([]*sdkpb.SecretResponse, error) {
	t.Helper()
	srv := httptest.NewServer(jsonRPCHandler(t, func(method string, raw json.RawMessage) (any, error) {
		require.Equal(t, confidentialrelay.MethodSecretsGet, method)
		var p confidentialrelay.SecretsRequestParams
		require.NoError(t, json.Unmarshal(raw, &p))
		results := resultsFor(p)
		return signSecretsBundleVaried(t, results, p, signers), nil
	}))
	t.Cleanup(srv.Close)

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		cfg,
		logger.Test(t),
		&stubKeychain{kp: kp},
		comb,
		signatureverifier.NewEd25519SignatureVerifier(),
		0, 0,
		maxSharesPerSigner,
	)

	return d.GetSecrets(
		context.Background(),
		"wf-secrets",
		[32]byte{1},
		&sdkpb.GetSecretsRequest{Requests: requests},
		"0x0123456789abcdef0123456789abcdef01234567",
		strings.Repeat("a", 64),
		"",
		nil,
	)
}

func secretResult(id confidentialrelay.SecretIdentifier, ciphertext string, shares []string) confidentialrelay.SecretsResponseResult {
	return confidentialrelay.SecretsResponseResult{
		Secrets: []confidentialrelay.SecretEntry{{
			ID:              id,
			Ciphertext:      base64.StdEncoding.EncodeToString([]byte(ciphertext)),
			EncryptedShares: shares,
		}},
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestGetSecrets_QuorumWithDifferentShareSubsets(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	vaultPK := "aabbcc"

	subsets := [][]string{
		{b64("s0"), b64("s1"), b64("s2")},
		{b64("s2"), b64("s3"), b64("s4")},
		{b64("s0"), b64("s5"), b64("s6")},
	}
	var capturedShares [][]byte
	var capturedPK []byte
	comb := &stubCombiner{aggregateFn: func(_ []byte, shares [][]byte, pk []byte, _ int) ([]byte, error) {
		capturedShares = shares
		capturedPK = pk
		return []byte("value"), nil
	}}

	resp, err := runSecretsDispatcher(t, signers, 2, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		results := make([]confidentialrelay.SecretsResponseResult, len(subsets))
		for i := range subsets {
			results[i] = secretResult(secretID, "ciphertext", subsets[i])
			results[i].RawVaultPublicKey = vaultPK
		}
		return results
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
	// The stubs pass shares through unchanged, so the combiner sees the distinct union.
	assert.Len(t, capturedShares, 7, "must union the distinct shares from all three signers")
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc}, capturedPK, "must use the agreed vault public key")
}

func TestGetSecrets_InsufficientDistinctSigners(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 2) // F=2 requires 3 distinct signers
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		t.Fatal("combiner must not run without quorum")
		return nil, nil
	}}

	_, err := runSecretsDispatcher(t, signers, 2, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			secretResult(secretID, "ciphertext", []string{b64("s0")}),
			secretResult(secretID, "ciphertext", []string{b64("s1")}),
		}
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no relay-DON result reached quorum")
}

func TestGetSecrets_DifferentCiphertextsAreGroupedSeparately(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 4) // F=2 requires 3 distinct signers
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	var capturedCiphertext []byte
	comb := &stubCombiner{aggregateFn: func(ciphertext []byte, _ [][]byte, _ []byte, _ int) ([]byte, error) {
		capturedCiphertext = ciphertext
		return []byte("value"), nil
	}}

	resp, err := runSecretsDispatcher(t, signers, 2, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			secretResult(secretID, "ct-a", []string{b64("s0")}),
			secretResult(secretID, "ct-a", []string{b64("s1")}),
			secretResult(secretID, "ct-a", []string{b64("s2")}),
			secretResult(secretID, "ct-b", []string{b64("s3")}),
		}
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, []byte("ct-a"), capturedCiphertext, "the three-signer ciphertext group must win")
}

func TestGetSecrets_DuplicateSignerDoesNotReachQuorum(t *testing.T) {
	t.Parallel()
	all := newRelaySigners(t, 2)
	signers := []relaySigner{all[0], all[0], all[1]} // only two distinct signers
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		t.Fatal("combiner must not run without quorum")
		return nil, nil
	}}

	_, err := runSecretsDispatcher(t, signers, 2, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			secretResult(secretID, "ciphertext", []string{b64("s0")}),
			secretResult(secretID, "ciphertext", []string{b64("s0")}),
			secretResult(secretID, "ciphertext", []string{b64("s1")}),
		}
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no relay-DON result reached quorum")
}

func TestGetSecrets_MalformedResultIsSkipped(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 4) // one malformed result must not block the honest quorum
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		return []byte("value"), nil
	}}

	resp, err := runSecretsDispatcher(t, signers, 2, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			{Secrets: nil}, // malformed: missing the requested secret
			secretResult(secretID, "ciphertext", []string{b64("s1")}),
			secretResult(secretID, "ciphertext", []string{b64("s2")}),
			secretResult(secretID, "ciphertext", []string{b64("s3")}),
		}
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
}

func TestGetSecrets_OversizedShareListIsTruncatedNotFatal(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3) // F=1 requires 2 distinct signers
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	var captured [][]byte
	comb := &stubCombiner{aggregateFn: func(_ []byte, shares [][]byte, _ []byte, _ int) ([]byte, error) {
		captured = shares
		return []byte("value"), nil
	}}

	flood := make([]string, types.DefaultMaxEncryptedSharesPerRelayResult+50)
	for i := range flood {
		flood[i] = b64(fmt.Sprintf("junk-%d", i))
	}

	resp, err := runSecretsDispatcher(t, signers, 1, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			secretResult(secretID, "ciphertext", flood),
			secretResult(secretID, "ciphertext", []string{b64("honest-1")}),
			secretResult(secretID, "ciphertext", []string{b64("honest-2")}),
		}
	})
	require.NoError(t, err, "one signer flooding shares must not fail the request")
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
	assert.Len(t, captured, types.DefaultMaxEncryptedSharesPerRelayResult+2, "flooding signer is capped, honest shares are kept")
	assert.Contains(t, captured, []byte("honest-1"))
	assert.Contains(t, captured, []byte("honest-2"))
}

func TestGetSecrets_InjectedShareCapIsApplied(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	var captured [][]byte
	comb := &stubCombiner{aggregateFn: func(_ []byte, shares [][]byte, _ []byte, _ int) ([]byte, error) {
		captured = shares
		return []byte("value"), nil
	}}

	const maxSharesPerSigner = 5
	flood := make([]string, maxSharesPerSigner+10)
	for i := range flood {
		flood[i] = b64(fmt.Sprintf("junk-%d", i))
	}

	cfg := relayDONConfig(signers, 1)
	cfg.MasterPublicKey = []byte("configured-master-public-key")
	resp, err := runSecretsDispatcherWithConfig(t, signers, cfg, comb, &stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: secretID.Key, Namespace: secretID.Namespace}},
		maxSharesPerSigner,
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			return []confidentialrelay.SecretsResponseResult{
				secretResult(secretID, "ciphertext", flood),
				secretResult(secretID, "ciphertext", []string{b64("honest-1")}),
				secretResult(secretID, "ciphertext", []string{b64("honest-2")}),
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
	assert.Len(t, captured, maxSharesPerSigner+2, "injected cap truncates the flooding signer")
}

func TestGetSecrets_SignerContributesSharesOncePerGroup(t *testing.T) {
	t.Parallel()
	all := newRelaySigners(t, 2)
	signers := []relaySigner{all[0], all[0], all[1]} // signer 0 appears twice
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	var captured [][]byte
	comb := &stubCombiner{aggregateFn: func(_ []byte, shares [][]byte, _ []byte, _ int) ([]byte, error) {
		captured = shares
		return []byte("value"), nil
	}}

	_, err := runSecretsDispatcher(t, signers, 1, comb, func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
		return []confidentialrelay.SecretsResponseResult{
			secretResult(secretID, "ciphertext", []string{b64("a")}),
			secretResult(secretID, "ciphertext", []string{b64("extra")}),
			secretResult(secretID, "ciphertext", []string{b64("b")}),
		}
	})
	require.NoError(t, err)
	assert.Len(t, captured, 2, "second entry from the same signer must be ignored")
	assert.NotContains(t, captured, []byte("extra"))
}

func TestGetSecrets_DuplicateRequestedSecretIDs(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 2)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		return []byte("value"), nil
	}}

	// The relay returns one entry per distinct ID, so a request naming the same
	// secret twice must still reach quorum.
	resp, err := runSecretsDispatcherFor(t, signers, 1, comb, &stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: "API_KEY", Namespace: "main"}, {Id: "API_KEY", Namespace: "main"}},
		func(p confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			require.Len(t, p.Secrets, 2)
			return []confidentialrelay.SecretsResponseResult{
				secretResult(secretID, "ciphertext", []string{b64("s0")}),
				secretResult(secretID, "ciphertext", []string{b64("s1")}),
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
}

func TestGetSecrets_MultipleSecretsUnionPerSecret(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3) // F=1 requires 2 distinct signers
	idA := confidentialrelay.SecretIdentifier{Key: "A", Namespace: "main"}
	idB := confidentialrelay.SecretIdentifier{Key: "B", Namespace: "main"}

	// Shares are merged per secret; the combiner records them by ciphertext.
	got := map[string][][]byte{}
	comb := &stubCombiner{aggregateFn: func(ct []byte, shares [][]byte, _ []byte, _ int) ([]byte, error) {
		got[string(ct)] = shares
		return []byte("value-" + string(ct)), nil
	}}

	entry := func(id confidentialrelay.SecretIdentifier, ct string, shares ...string) confidentialrelay.SecretEntry {
		return secretResult(id, ct, shares).Secrets[0]
	}
	resp, err := runSecretsDispatcherFor(t, signers, 1, comb, &stubKeypair{pub: []byte("enclave-pub")},
		// B is requested first; responses must follow request order.
		[]*sdkpb.SecretRequest{{Id: "B", Namespace: "main"}, {Id: "A", Namespace: "main"}},
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			return []confidentialrelay.SecretsResponseResult{
				{Secrets: []confidentialrelay.SecretEntry{entry(idA, "ct-a", b64("a0"), b64("a1")), entry(idB, "ct-b", b64("b0"))}},
				{Secrets: []confidentialrelay.SecretEntry{entry(idB, "ct-b", b64("b1")), entry(idA, "ct-a", b64("a1"), b64("a2"))}},
				{Secrets: []confidentialrelay.SecretEntry{entry(idA, "ct-a", b64("a3")), entry(idB, "ct-b", b64("b2"))}},
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 2)
	assert.Equal(t, "B", resp[0].GetSecret().GetId())
	assert.Equal(t, "value-ct-b", resp[0].GetSecret().GetValue())
	assert.Equal(t, "A", resp[1].GetSecret().GetId())
	assert.Equal(t, "value-ct-a", resp[1].GetSecret().GetValue())

	assert.ElementsMatch(t, [][]byte{[]byte("a0"), []byte("a1"), []byte("a2"), []byte("a3")}, got["ct-a"])
	assert.ElementsMatch(t, [][]byte{[]byte("b0"), []byte("b1"), []byte("b2")}, got["ct-b"])
}

func TestGetSecrets_MultipleSecretsOneWithoutQuorumFailsRequest(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3) // F=1 requires 2 distinct signers
	idA := confidentialrelay.SecretIdentifier{Key: "A", Namespace: "main"}
	idB := confidentialrelay.SecretIdentifier{Key: "B", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		t.Fatal("combiner must not run when any secret lacks quorum")
		return nil, nil
	}}

	_, err := runSecretsDispatcherFor(t, signers, 1, comb, &stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: "A", Namespace: "main"}, {Id: "B", Namespace: "main"}},
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			result := func(ctB string) confidentialrelay.SecretsResponseResult {
				return confidentialrelay.SecretsResponseResult{Secrets: []confidentialrelay.SecretEntry{
					secretResult(idA, "ct-a", []string{b64("a")}).Secrets[0],
					secretResult(idB, ctB, []string{b64("b")}).Secrets[0],
				}}
			}
			// A is agreed by everyone; B has three different ciphertexts.
			return []confidentialrelay.SecretsResponseResult{result("ct-b0"), result("ct-b1"), result("ct-b2")}
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no relay-DON result reached quorum")
}

func TestGetSecrets_SecretsWinningOnDifferentVaultKeysFailsRequest(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 4) // F=1 requires 2 distinct signers
	idA := confidentialrelay.SecretIdentifier{Key: "A", Namespace: "main"}
	idB := confidentialrelay.SecretIdentifier{Key: "B", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		t.Fatal("combiner must not run when secrets disagree on the vault public key")
		return nil, nil
	}}

	_, err := runSecretsDispatcherFor(t, signers, 1, comb, &stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: "A", Namespace: "main"}, {Id: "B", Namespace: "main"}},
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			result := func(pk, ctA, ctB string) confidentialrelay.SecretsResponseResult {
				return confidentialrelay.SecretsResponseResult{
					RawVaultPublicKey: pk,
					Secrets: []confidentialrelay.SecretEntry{
						secretResult(idA, ctA, []string{b64("a")}).Secrets[0],
						secretResult(idB, ctB, []string{b64("b")}).Secrets[0],
					},
				}
			}
			// A reaches quorum only under key aa, B only under key bb.
			return []confidentialrelay.SecretsResponseResult{
				result("aa", "ct-a", "ct-b0"),
				result("aa", "ct-a", "ct-b1"),
				result("bb", "ct-a2", "ct-b"),
				result("bb", "ct-a3", "ct-b"),
			}
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relay-DON secrets results disagree on vault public key for main/B")
}

// A faulty signer's invalid node-0 share must not displace the honest node-0
// share. Uses the real TDH2 combiner.
func TestGetSecrets_InvalidShareDoesNotShadowValidShareForSameIndex(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 2) // F=1 requires 2 distinct signers
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}

	_, pk, privShares, err := tdh2easy.GenerateKeys(2, 3)
	require.NoError(t, err)
	ciphertext, err := tdh2easy.Encrypt(pk, []byte("vault secret"))
	require.NoError(t, err)
	otherCiphertext, err := tdh2easy.Encrypt(pk, []byte("other secret"))
	require.NoError(t, err)

	marshalShare := func(c *tdh2easy.Ciphertext, ps *tdh2easy.PrivateShare) (*tdh2easy.DecryptionShare, string) {
		share, err := tdh2easy.Decrypt(c, ps)
		require.NoError(t, err)
		raw, err := share.Marshal()
		require.NoError(t, err)
		return share, base64.StdEncoding.EncodeToString(raw)
	}
	honest0Share, honest0 := marshalShare(ciphertext, privShares[0])
	_, honest1 := marshalShare(ciphertext, privShares[1])
	// A real node-0 share for a different ciphertext: well-formed with index 0,
	// but invalid for the requested ciphertext.
	forged0Share, forged0 := marshalShare(otherCiphertext, privShares[0])
	require.Equal(t, honest0Share.Index(), forged0Share.Index())
	require.Error(t, tdh2easy.VerifyShare(ciphertext, pk, forged0Share))

	ctBytes, err := ciphertext.Marshal()
	require.NoError(t, err)
	pkBytes, err := pk.Marshal()
	require.NoError(t, err)

	cfg := relayDONConfig(signers, 1)
	cfg.T = 2
	resp, err := runSecretsDispatcherWithConfig(t, signers, cfg, combiner.NewTDH2EasyCombiner(),
		&stubKeypair{pub: []byte("enclave-pub")},
		[]*sdkpb.SecretRequest{{Id: "API_KEY", Namespace: "main"}},
		0,
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			result := func(shares ...string) confidentialrelay.SecretsResponseResult {
				return confidentialrelay.SecretsResponseResult{
					RawVaultPublicKey: hex.EncodeToString(pkBytes),
					Secrets: []confidentialrelay.SecretEntry{{
						ID:              secretID,
						Ciphertext:      base64.StdEncoding.EncodeToString(ctBytes),
						EncryptedShares: shares,
					}},
				}
			}
			// The faulty signer is first, so its share precedes the honest one.
			return []confidentialrelay.SecretsResponseResult{
				result(forged0),
				result(honest0, honest1),
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	require.Empty(t, resp[0].GetError().GetError())
	assert.Equal(t, "vault secret", resp[0].GetSecret().GetValue())
}

// selectiveKeypair fails to decrypt shares starting with "bad", like shares
// encrypted to the wrong key.
type selectiveKeypair struct{ stubKeypair }

func (k *selectiveKeypair) Decrypt(b []byte) ([]byte, error) {
	if strings.HasPrefix(string(b), "bad") {
		return nil, fmt.Errorf("cannot decrypt share")
	}
	return b, nil
}

func TestGetSecrets_UndecryptableSharesAreSkipped(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 3)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	var captured [][]byte
	comb := &stubCombiner{aggregateFn: func(_ []byte, shares [][]byte, _ []byte, _ int) ([]byte, error) {
		captured = shares
		return []byte("value"), nil
	}}

	resp, err := runSecretsDispatcherFor(t, signers, 1, comb,
		&selectiveKeypair{stubKeypair{pub: []byte("enclave-pub")}},
		[]*sdkpb.SecretRequest{{Id: "API_KEY", Namespace: "main"}},
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			return []confidentialrelay.SecretsResponseResult{
				secretResult(secretID, "ciphertext", []string{b64("bad-1"), b64("good-1")}),
				secretResult(secretID, "ciphertext", []string{"!!not-base64!!", b64("good-2")}),
				secretResult(secretID, "ciphertext", []string{b64("good-3")}),
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "value", resp[0].GetSecret().GetValue())
	assert.ElementsMatch(t, [][]byte{[]byte("good-1"), []byte("good-2"), []byte("good-3")}, captured,
		"only decodable and decryptable shares reach the combiner")
}

func TestGetSecrets_NoDecryptableSharesReturnsPerSecretError(t *testing.T) {
	t.Parallel()
	signers := newRelaySigners(t, 2)
	secretID := confidentialrelay.SecretIdentifier{Key: "API_KEY", Namespace: "main"}
	comb := &stubCombiner{aggregateFn: func([]byte, [][]byte, []byte, int) ([]byte, error) {
		t.Fatal("combiner must not run without any decryptable share")
		return nil, nil
	}}

	resp, err := runSecretsDispatcherFor(t, signers, 1, comb,
		&selectiveKeypair{stubKeypair{pub: []byte("enclave-pub")}},
		[]*sdkpb.SecretRequest{{Id: "API_KEY", Namespace: "main"}},
		func(confidentialrelay.SecretsRequestParams) []confidentialrelay.SecretsResponseResult {
			return []confidentialrelay.SecretsResponseResult{
				secretResult(secretID, "ciphertext", []string{b64("bad-1")}),
				secretResult(secretID, "ciphertext", []string{b64("bad-2")}),
			}
		})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Contains(t, resp[0].GetError().GetError(), "no decryptable shares (2 skipped)")
}
