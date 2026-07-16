package util

import (
	"crypto/rand"
	"fmt"

	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"golang.org/x/crypto/nacl/box"
)

// TDH2NACLBoxComputeEncryptedDecryptionShare computes an encrypted decryption share for a given ciphertext and private key share.
// It uses TDH2 to calculate the decryption share and NaCl box to encrypt the decryption share with the recipient's public key.
// If the TDH2 public key is mismatched against the private key share used, computation will fail.
func TDH2NACLBoxComputeEncryptedDecryptionShare(
	privateKeyShare tdh2easy.PrivateShare,
	publicKey tdh2easy.PublicKey,
	ciphertext tdh2easy.Ciphertext,
	recipientPublicKey [32]byte,
) ([]byte, error) {
	// Compute the decryption share.
	decShare, err := tdh2easy.Decrypt(&ciphertext, &privateKeyShare)
	if err != nil {
		return nil, fmt.Errorf("failed to generate decryption share: %w", err)
	}
	err = tdh2easy.VerifyShare(&ciphertext, &publicKey, decShare)
	if err != nil {
		return nil, fmt.Errorf("failed to verify decryption share: %w", err)
	}
	decShareBytes, err := decShare.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decryption share: %w", err)
	}

	// Encrypt the decryption share using the recipient's public key.
	encryptedDecryptionShare, err := box.SealAnonymous(nil, decShareBytes, &recipientPublicKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt decryption share: %w", err)
	}

	return encryptedDecryptionShare, nil
}

type invalidShare struct {
	index int
	share []byte
	err   error
}

// TDH2AggregateDecryptionShares aggregates TDH2 decryption shares for a given ciphertext.
// It validates each share against the ciphertext and public key. For an invalid share, the share is collected and
// the function continues. If a threshold of valid shares is not reached, it returns an error containing the faulty shares.
// Otherwise, it proceeds to aggregate the valid shares and returns the result.
func TDH2AggregateDecryptionShares(ciphertext tdh2easy.Ciphertext, shares [][]byte, publicKey tdh2easy.PublicKey, threshold int) ([]byte, error) {
	// Gather all valid shares.
	var decShares []*tdh2easy.DecryptionShare
	var invalidShares []invalidShare
	for i, s := range shares {
		var share tdh2easy.DecryptionShare
		if err := share.Unmarshal(s); err != nil {
			invalidShares = append(invalidShares, invalidShare{index: i, share: s, err: err})
			continue
		}

		if err := tdh2easy.VerifyShare(&ciphertext, &publicKey, &share); err != nil {
			invalidShares = append(invalidShares, invalidShare{index: i, share: s, err: err})
			continue
		}
		decShares = append(decShares, &share)
		if len(decShares) == threshold {
			break
		}
	}

	// If a threshold of valid shares is not reached, return faulty shares.
	if len(decShares) < threshold {
		var errDetails string
		for _, is := range invalidShares {
			errDetails += fmt.Sprintf("share %d (%x): %v; ", is.index, is.share, is.err)
		}
		if len(invalidShares) == 0 {
			errDetails = "none"
		}
		return nil, fmt.Errorf("not enough valid shares to decrypt (%d/%d). invalid shares: %s",
			len(decShares), threshold, errDetails)
	}

	// Aggregate threshold of valid shares.
	decrypted, err := tdh2easy.Aggregate(&ciphertext, decShares, len(decShares))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt payload: %w", err)
	}

	return decrypted, nil
}
