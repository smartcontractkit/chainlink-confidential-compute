package signatureverifier

import (
	"crypto/ed25519"
	"fmt"
)

type ed25519SignatureVerifier struct{}

func NewEd25519SignatureVerifier() SignatureVerifier {
	return &ed25519SignatureVerifier{}
}

var _ SignatureVerifier = (*ed25519SignatureVerifier)(nil)

// VerifySignature verifies the signature of a message against a list of allowed signers.
func (v *ed25519SignatureVerifier) VerifySignature(hash []byte, signature []byte, allowedSigners [][]byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: expected %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}

	for _, allowedSigner := range allowedSigners {
		pubKey := ed25519.PublicKey(allowedSigner)
		if ed25519.Verify(pubKey, hash, signature) {
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("signature not from any allowed signer")
}
