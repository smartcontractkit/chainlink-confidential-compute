package combiner

import (
	"fmt"

	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
)

type tdh2EasyCombiner struct {
}

var _ Combiner = (*tdh2EasyCombiner)(nil)

func NewTDH2EasyCombiner() *tdh2EasyCombiner {
	return &tdh2EasyCombiner{}
}

func (c *tdh2EasyCombiner) AggregateShares(ciphertext []byte, shares [][]byte, tdh2PublicKeyBytes []byte, threshold int) ([]byte, error) {
	var publicKey tdh2easy.PublicKey
	if err := publicKey.Unmarshal(tdh2PublicKeyBytes); err != nil {
		return nil, fmt.Errorf("cannot unmarshal public key: %w", err)
	}

	var ctxt tdh2easy.Ciphertext
	if err := ctxt.UnmarshalVerify(ciphertext, &publicKey); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ciphertext: %w", err)
	}

	decrypted, err := util.TDH2AggregateDecryptionShares(ctxt, shares, publicKey, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate decryption shares: %w", err)
	}

	return decrypted, nil
}

// VerifyShare is not implemented in favor of doing verification inside the AggregateShares function.
func (c *tdh2EasyCombiner) VerifyShare(ciphertext []byte, tdh2PublicKey []byte, share []byte) error {
	return fmt.Errorf("not implemented")
}
