package signatureverifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEd25519SignatureVerifier_VerifySignature(t *testing.T) {
	verifier := NewEd25519SignatureVerifier()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	message := []byte("test message")

	// Happy path.
	signature := ed25519.Sign(privKey, message)
	allowedSigners := [][]byte{pubKey}
	p, err := verifier.VerifySignature(message, signature, allowedSigners)
	if err != nil {
		t.Errorf("Expected valid signature to pass verification, got error: %v", err)
	}
	require.True(t, bytes.Equal(p, pubKey), "Expected public key to match the one used for signing")

	// Disallowed signer.
	otherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	allowedSigners = [][]byte{otherPubKey}
	_, err = verifier.VerifySignature(message, signature, allowedSigners)
	require.Error(t, err)
	require.True(t, err.Error() == "signature not from any allowed signer")

	// Invalid signature length.
	invalidSignature := []byte("too short")
	allowedSigners = [][]byte{pubKey}
	_, err = verifier.VerifySignature(message, invalidSignature, allowedSigners)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid signature length")

	// Multiple allowed signers.
	anotherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	allowedSigners = [][]byte{anotherPubKey, pubKey, otherPubKey}
	p, err = verifier.VerifySignature(message, signature, allowedSigners)
	require.NoError(t, err)
	require.True(t, bytes.Equal(p, pubKey))
}
