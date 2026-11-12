package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

var (
	votesSecretA = confidentialrelay.SecretIdentifier{Key: "A", Namespace: "main"}
	votesSecretB = confidentialrelay.SecretIdentifier{Key: "B", Namespace: "main"}
)

func signerKeyHash(n byte) [32]byte { return [32]byte{n} }

func nodeResponse(vaultPublicKey string, entries ...confidentialrelay.SecretEntry) confidentialrelay.SecretsResponseResult {
	return confidentialrelay.SecretsResponseResult{Secrets: entries, RawVaultPublicKey: vaultPublicKey}
}

func secretEntry(id confidentialrelay.SecretIdentifier, ciphertext string, shares ...string) confidentialrelay.SecretEntry {
	return confidentialrelay.SecretEntry{ID: id, Ciphertext: ciphertext, EncryptedShares: shares}
}

func testSecretVotes(requested []confidentialrelay.SecretIdentifier) *secretVotes {
	return newSecretVotes(requested, types.DefaultMaxEncryptedSharesPerRelayResult)
}

func TestSecretVotes_ValidateNodeResponse(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA, votesSecretB, votesSecretA})
	secretC := confidentialrelay.SecretIdentifier{Key: "C", Namespace: "main"}

	require.NoError(t, votes.validateNodeResponse(nodeResponse("pk", secretEntry(votesSecretB, "ct"), secretEntry(votesSecretA, "ct"))),
		"a duplicated request ID expects one entry, in any order")
	assert.ErrorContains(t, votes.validateNodeResponse(nodeResponse("pk", secretEntry(votesSecretA, "ct"))), "expected 2 secret responses, got 1")
	assert.ErrorContains(t, votes.validateNodeResponse(nodeResponse("pk", secretEntry(votesSecretA, "ct"), secretEntry(secretC, "ct"))), "unexpected secret main/C")
	assert.ErrorContains(t, votes.validateNodeResponse(nodeResponse("pk", secretEntry(votesSecretA, "ct"), secretEntry(votesSecretA, "ct"))), "duplicate secret main/A")
}

func TestSecretVotes_SignerCountsOncePerCandidate(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA})
	votes.addVote(signerKeyHash(1), nodeResponse("pk", secretEntry(votesSecretA, "ct", "s1")))
	votes.addVote(signerKeyHash(1), nodeResponse("pk", secretEntry(votesSecretA, "ct", "extra")))

	_, err := votes.selectWinners(2)
	var noQuorum noSecretQuorumError
	require.True(t, errors.As(err, &noQuorum), "one signer voting twice must not reach a quorum of 2")
	assert.Equal(t, votesSecretA, noQuorum.secret)

	votes.addVote(signerKeyHash(2), nodeResponse("pk", secretEntry(votesSecretA, "ct", "s2")))
	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"s1", "s2"}, combined.Secrets[0].EncryptedShares, "the repeated vote's shares are ignored")
}

func TestSecretVotes_CapsSharesPerSigner(t *testing.T) {
	t.Parallel()
	const maxSharesPerSigner = 8
	votes := newSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA}, maxSharesPerSigner)
	flood := make([]string, maxSharesPerSigner+10)
	for i := range flood {
		flood[i] = fmt.Sprintf("junk-%d", i)
	}

	assert.Equal(t, 10, votes.addVote(signerKeyHash(1), nodeResponse("pk", secretEntry(votesSecretA, "ct", flood...))))
	assert.Zero(t, votes.addVote(signerKeyHash(2), nodeResponse("pk", secretEntry(votesSecretA, "ct", "honest"))))

	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	assert.Len(t, combined.Secrets[0].EncryptedShares, maxSharesPerSigner+1)
}

func TestSecretVotes_RemovesExactDuplicateShares(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA})
	votes.addVote(signerKeyHash(1), nodeResponse("pk", secretEntry(votesSecretA, "ct", "s0", "s1")))
	votes.addVote(signerKeyHash(2), nodeResponse("pk", secretEntry(votesSecretA, "ct", "s1", "s2")))

	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	assert.Equal(t, []string{"s0", "s1", "s2"}, combined.Secrets[0].EncryptedShares)
	assert.Equal(t, "pk", combined.RawVaultPublicKey)
}

func TestSecretVotes_MostSignersWinsThenTieBreak(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA})
	votes.addVote(signerKeyHash(1), nodeResponse("pk", secretEntry(votesSecretA, "ct-b")))
	votes.addVote(signerKeyHash(2), nodeResponse("pk", secretEntry(votesSecretA, "ct-b")))
	votes.addVote(signerKeyHash(3), nodeResponse("pk", secretEntry(votesSecretA, "ct-a")))
	votes.addVote(signerKeyHash(4), nodeResponse("pk", secretEntry(votesSecretA, "ct-a")))

	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	assert.Equal(t, "ct-a", combined.Secrets[0].Ciphertext, "a 2-2 tie goes to the smaller tie-break key")

	votes.addVote(signerKeyHash(5), nodeResponse("pk", secretEntry(votesSecretA, "ct-b")))
	combined, err = votes.selectWinners(2)
	require.NoError(t, err)
	assert.Equal(t, "ct-b", combined.Secrets[0].Ciphertext, "more signers wins over the tie-break")
}

func TestSecretVotes_WinnersMustShareVaultPublicKey(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA, votesSecretB})
	// A reaches quorum only under key "aa", B only under key "bb".
	votes.addVote(signerKeyHash(1), nodeResponse("aa", secretEntry(votesSecretA, "ct-a"), secretEntry(votesSecretB, "ct-b0")))
	votes.addVote(signerKeyHash(2), nodeResponse("aa", secretEntry(votesSecretA, "ct-a"), secretEntry(votesSecretB, "ct-b1")))
	votes.addVote(signerKeyHash(3), nodeResponse("bb", secretEntry(votesSecretA, "ct-a2"), secretEntry(votesSecretB, "ct-b")))
	votes.addVote(signerKeyHash(4), nodeResponse("bb", secretEntry(votesSecretA, "ct-a3"), secretEntry(votesSecretB, "ct-b")))

	_, err := votes.selectWinners(2)
	assert.ErrorContains(t, err, "relay-DON secrets results disagree on vault public key for main/B")
}

func TestSecretVotes_TiedSecretsResolveToSameVaultPublicKey(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretA, votesSecretB})
	// Signers split 2-2 between keys "aa" and "bb", and each key has its own
	// ciphertexts. Ordering ties by ciphertext would pick "bb" for A and "aa" for B.
	votes.addVote(signerKeyHash(1), nodeResponse("aa", secretEntry(votesSecretA, "ct-z"), secretEntry(votesSecretB, "ct-a")))
	votes.addVote(signerKeyHash(2), nodeResponse("aa", secretEntry(votesSecretA, "ct-z"), secretEntry(votesSecretB, "ct-a")))
	votes.addVote(signerKeyHash(3), nodeResponse("bb", secretEntry(votesSecretA, "ct-y"), secretEntry(votesSecretB, "ct-b")))
	votes.addVote(signerKeyHash(4), nodeResponse("bb", secretEntry(votesSecretA, "ct-y"), secretEntry(votesSecretB, "ct-b")))

	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	assert.Equal(t, "aa", combined.RawVaultPublicKey)
	assert.Equal(t, "ct-z", combined.Secrets[0].Ciphertext)
	assert.Equal(t, "ct-a", combined.Secrets[1].Ciphertext)
}

func TestSecretVotes_ResultFollowsRequestOrder(t *testing.T) {
	t.Parallel()
	votes := testSecretVotes([]confidentialrelay.SecretIdentifier{votesSecretB, votesSecretA})
	for signer := byte(1); signer <= 2; signer++ {
		votes.addVote(signerKeyHash(signer), nodeResponse("pk", secretEntry(votesSecretA, "ct-a"), secretEntry(votesSecretB, "ct-b")))
	}

	combined, err := votes.selectWinners(2)
	require.NoError(t, err)
	require.Len(t, combined.Secrets, 2)
	assert.Equal(t, votesSecretB, combined.Secrets[0].ID)
	assert.Equal(t, votesSecretA, combined.Secrets[1].ID)
}
