// This package provides the `Combiner` for aggregating and verifying decryption key shares.
// It also provides an implementation for TDH2 shares.

package combiner

type Combiner interface {
	AggregateShares(ciphertext []byte, shares [][]byte, publicKey []byte, threshold int) (message []byte, err error)
	VerifyShare(ciphertext []byte, publicKey []byte, share []byte) error
}
