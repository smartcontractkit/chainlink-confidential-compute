// This package provides an interface for verifying a signature against a list of allowed signers.
// It also includes an implementation that uses Ed25519 signature verification.
package signatureverifier

type SignatureVerifier interface {
	VerifySignature(hash []byte, signature []byte, allowedSigners [][]byte) (signer []byte, err error)
}
