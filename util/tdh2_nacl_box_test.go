package util

import (
	"crypto/rand"
	"testing"

	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

type TestData struct {
	publicKey           *tdh2easy.PublicKey
	privateShare        *tdh2easy.PrivateShare
	ciphertext          *tdh2easy.Ciphertext
	recipientPublicKey  *[32]byte
	recipientPrivateKey *[32]byte
	message             []byte
}

func setupTest(t *testing.T) *TestData {
	_, publicKey, privateShares, err := tdh2easy.GenerateKeys(1, 1)
	require.NoError(t, err)
	require.Len(t, privateShares, 1)
	privateShare := privateShares[0]

	message := []byte("test message for encrypted decryption share")

	ciphertext, err := tdh2easy.Encrypt(publicKey, message)
	require.NoError(t, err)

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return &TestData{
		publicKey:           publicKey,
		privateShare:        privateShare,
		ciphertext:          ciphertext,
		recipientPublicKey:  recipientPublicKey,
		recipientPrivateKey: recipientPrivateKey,
		message:             message,
	}
}

func TestComputeEncryptedDecryptionShare(t *testing.T) {
	t.Parallel()
	td := setupTest(t)

	// Compute the encrypted decryption share.
	encryptedDecShare, err := TDH2NACLBoxComputeEncryptedDecryptionShare(
		*td.privateShare,
		*td.publicKey,
		*td.ciphertext,
		*td.recipientPublicKey,
	)
	require.NoError(t, err)
	require.NotNil(t, encryptedDecShare)

	// Decrypt the encrypted decryption share using the recipient's private key.
	decShareBytes, ok := box.OpenAnonymous(nil, encryptedDecShare, td.recipientPublicKey, td.recipientPrivateKey)
	require.True(t, ok, "failed to open anonymous box")
	require.NotNil(t, decShareBytes)

	// Verify that the decryption share is valid.
	var decShare tdh2easy.DecryptionShare
	err = decShare.Unmarshal(decShareBytes)
	require.NoError(t, err)
	err = tdh2easy.VerifyShare(td.ciphertext, td.publicKey, &decShare)
	require.NoError(t, err)
}

func TestComputeEncryptedDecryptionShareMismatchedKeys(t *testing.T) {
	t.Parallel()
	td := setupTest(t)

	_, mismatchedPublicKey, _, err := tdh2easy.GenerateKeys(1, 1)
	require.NoError(t, err)

	_, err = TDH2NACLBoxComputeEncryptedDecryptionShare(
		*td.privateShare,
		*mismatchedPublicKey,
		*td.ciphertext,
		*td.recipientPublicKey,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify decryption share")
}

// A tdh2easy 2-of-3 public key, the ciphertext of "vault secret" and all three
// decryption shares. Shares come from vault DON nodes, which may run a
// different tdh2 version, so the serialized formats are pinned here.
const (
	goldenTDH2PublicKey  = `{"Group":"P256","G_bar":"BBarahyeHz+DF55JmLV3LmBGL+mwatUrSKHfC332sGf0ij06EWPvrRSvfRuBVUVpvnfxghIuIKibfxtLfTwK7jc=","H":"BMsHxqCTAqq8RXeRVdqNbUf1ru0gLIIZijobHXSi/03MZT5wHWdBDxGZxX1yqAZtYcLxBhOFz3JecyH6PG2b2qE=","HArray":["BOSVkHrKyCmJbgFeWnAtrS5B/rj0uEVC/4sXud8UB476oPwrShqeEM4pYTBTmWIKl+MAYcMDPeXqv8apVW5OrBc=","BEJpEkxEP/G/UVR+vcqF2R3HeORKyylAzARbmFd463w9mkXEYIzyD+0G/vC5X8PD+XDEpaceynWyF90sxYI02pk=","BA5ArRNW6r7aioqXIfNloVJEx7khxjoLl24XMSvdoiPQit48NeGcS1kEVvikSoDvH22v4c5Er60dRTFjXn01gls="]}`
	goldenTDH2Ciphertext = `{"TDH2Ctxt":"eyJHcm91cCI6IlAyNTYiLCJDIjoieTdXUlZLRzVFcGY3dmZOOThBeXVaTVl5RGVKS0ZJbUtsa1lYZS9rL2JrND0iLCJMYWJlbCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9IiwiVSI6IkJIaWFaaDFFanMybXMwc0dSUEJERXlRdjJoMDdXQ2JKVjFDWmN0enhqOG1uY2c1SHBDQ1FZOXBjdXdGN2FsV1R0bU5qOGNaVVIrNy9WaFM1VnFiN3dyRT0iLCJVX2JhciI6IkJITHQyOWIyNkViMXl5dmpndGwxZERua3g0bFN2SmVHWnB5Q0JlL3ZkakZXV2lYMlVnRkd3d3RvOGtBNEg4Q2MwUTRIbm9oYW5sTkV3RUx6R0NsWjR3ND0iLCJFIjoiZi9hUUc5Vy9seHYzQ2lGTUpqQnlyNmphTUphMW9nNFU2aHM5bW4wbEVwdz0iLCJGIjoiMUJ3VDZNRk5vOFc0NEdiRWowRENNZ2FSbHFPYmg0QngyNFBYVm40S2dIOD0ifQ==","SymCtxt":"51ofVVPsYfeowMk2b9nfYKYpooyoRJiyAUygfg==","Nonce":"Zf8kx82ejjLkPrXp"}`
)

var goldenTDH2Shares = []string{
	`{"Group":"P256","Index":0,"U_i":"BGImzTjh6KlhAisTeB5m+LlIMNMjQgGfPmQ9HnuNfvy2kufIV96kgMzkF6lkFLQ5VcYu6S/q4KVKlGdvjVNXses=","E_i":"5x4mA3EFoGCug72ISKhlpfoJrxyqgZjTnZBq50EPC9M=","F_i":"FY5LQ8EnPUj0hwKst1EayrpTXcfMTq2I0ccoDmrgywE="}`,
	`{"Group":"P256","Index":1,"U_i":"BA9wL3N9lPj3BXZjKpGtbT0DMqgJ3L+5GvOOB0EitrZcYk1EQc/tMtPqHB1YRYVPn5lkP+GgRPWwNgdeYkoR7xY=","E_i":"iACD/RUoa9gPesCqri2KW3t5elXw8zt3Uli1yaNQ+Q0=","F_i":"AhSirxIJXIYOVZo4xNAemRlaTBFnGTOEpRgCwb10EMg="}`,
	`{"Group":"P256","Index":2,"U_i":"BC/K/fvRRu+NxF/X9uXVl+8Odl56yvIXMTuREcKWJ4xAqyWUUjlJAUFpCDmcxcpoHfZ6pHEBOrAr5kTMatXPag8=","E_i":"UsdTYoZXUR06eb3nlHS94LUdEVGlpKnpoHhP8YzFzQU=","F_i":"PFArpvQmtRK4TnFgvLqX4dqpAPoG/tV7+Zh/1PxqbzI="}`,
}

func TestTDH2AggregateDecryptionShares_Golden(t *testing.T) {
	var publicKey tdh2easy.PublicKey
	require.NoError(t, publicKey.Unmarshal([]byte(goldenTDH2PublicKey)))
	var ciphertext tdh2easy.Ciphertext
	require.NoError(t, ciphertext.UnmarshalVerify([]byte(goldenTDH2Ciphertext), &publicKey))

	shares := [][]byte{[]byte(goldenTDH2Shares[2]), []byte("not a share"), []byte(goldenTDH2Shares[0])}
	plaintext, err := TDH2AggregateDecryptionShares(ciphertext, shares, publicKey, 2)
	require.NoError(t, err)
	assert.Equal(t, "vault secret", string(plaintext))

	_, err = TDH2AggregateDecryptionShares(ciphertext, shares[:2], publicKey, 2)
	require.ErrorContains(t, err, "not enough valid shares to decrypt (1/2)")
	require.ErrorContains(t, err, "share 1:")
}
