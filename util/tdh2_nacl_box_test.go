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
