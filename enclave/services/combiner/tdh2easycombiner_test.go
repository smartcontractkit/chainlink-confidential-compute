package combiner_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
)

func TestTDH2EasyCombiner_AggregateShares(t *testing.T) {
	// Use node sets of various sizes.
	thresholds := []int{1, 3, 5, 10}
	nodeCount := []int{1, 5, 10, 16}

	message := []byte("this is a test message for TDH2 encryption")

	// Test all node sets.
	for i, threshold := range thresholds {
		n := nodeCount[i%len(nodeCount)]
		assert.LessOrEqual(t, threshold, n, "Threshold must be less than or equal to number of nodes")

		t.Run(fmt.Sprintf("valid shares: threshold %d of %d", threshold, n), func(t *testing.T) {
			// Generate keys for nodes.
			_, publicKey, privateShares, err := tdh2easy.GenerateKeys(threshold, n)
			require.NoError(t, err)
			require.Equal(t, n, len(privateShares))

			// Encrypt the message.
			ciphertext, err := tdh2easy.Encrypt(publicKey, message)
			require.NoError(t, err)
			ciphertextBytes, err := ciphertext.Marshal()
			require.NoError(t, err)

			// Generate & verify decryption shares for each node.
			decryptionShares := make([][]byte, n)
			for i, share := range privateShares {
				decShare, err := tdh2easy.Decrypt(ciphertext, share)
				require.NoError(t, err)
				err = tdh2easy.VerifyShare(ciphertext, publicKey, decShare)
				require.NoError(t, err)
				decShareBytes, err := decShare.Marshal()
				require.NoError(t, err)
				decryptionShares[i] = decShareBytes
			}

			// Instantiate a tdh2easycombiner.
			tdh2Combiner := combiner.NewTDH2EasyCombiner()
			require.NoError(t, err)

			// Aggregate shares to recover & verify the original message.
			pubKeyBytes, err := publicKey.Marshal()
			require.NoError(t, err)
			recoveredMessage, err := tdh2Combiner.AggregateShares(ciphertextBytes, decryptionShares, pubKeyBytes, threshold)
			require.NoError(t, err)
			require.True(t, bytes.Equal(message, recoveredMessage))

			// Test with minimum shares needed (threshold).
			t.Run("minimum shares", func(t *testing.T) {
				// Use only threshold number of shares
				minShares := decryptionShares[:threshold]
				recoveredMessage, err := tdh2Combiner.AggregateShares(ciphertextBytes, minShares, pubKeyBytes, threshold)
				require.NoError(t, err)
				require.True(t, bytes.Equal(message, recoveredMessage))
			})

			// Test with invalid shares.
			t.Run("invalid shares", func(t *testing.T) {
				// t-1 valid shares, no invalid shares.
				if threshold > 1 {
					insufficientShares := decryptionShares[:threshold-1]
					_, err := tdh2Combiner.AggregateShares(ciphertextBytes, insufficientShares, pubKeyBytes, threshold)
					require.Error(t, err)
					require.Contains(t, err.Error(), fmt.Sprintf("not enough valid shares to decrypt (%d/%d). invalid shares: none",
						len(insufficientShares), threshold))
				}

				// Invalid ciphertext.
				invalidCiphertext := []byte("invalid ciphertext")
				_, err := tdh2Combiner.AggregateShares(invalidCiphertext, decryptionShares, pubKeyBytes, threshold)
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot unmarshal ciphertext")

				// Mix of valid and invalid shares.
				if threshold < n {
					// Generate a threshold of decryption shares with its final share being invalid.
					invalidShare := make([]byte, 200)
					_, err = rand.Read(invalidShare)
					require.NoError(t, err)
					mixedShares := make([][]byte, threshold)
					copy(mixedShares, decryptionShares[:threshold-1])
					mixedShares[threshold-1] = invalidShare

					// Aggregate shares. Assert a threshold of valid shares is not met due to the last share.
					_, err = tdh2Combiner.AggregateShares(ciphertextBytes, mixedShares, pubKeyBytes, threshold)
					require.Error(t, err)
					require.Contains(t, err.Error(), fmt.Sprintf("not enough valid shares to decrypt (%d/%d). invalid shares: share %d", threshold-1, threshold, threshold-1))

					// If more valid shares are added, the threshold of valid shares is met and aggregation succeeds.
					if threshold+1 <= n {
						mixedWithEnoughValidShares := make([][]byte, threshold+1)
						copy(mixedWithEnoughValidShares, decryptionShares[:threshold])
						mixedWithEnoughValidShares[threshold] = invalidShare
						recoveredMessage, err := tdh2Combiner.AggregateShares(ciphertextBytes, mixedWithEnoughValidShares, pubKeyBytes, threshold)
						require.NoError(t, err)
						require.True(t, bytes.Equal(message, recoveredMessage))
					}
				}
			})
		})
	}
}

// Test that VerifyShare returns an error as it's not implemented
func TestVerifyShare(t *testing.T) {
	combiner := combiner.NewTDH2EasyCombiner()
	err := combiner.VerifyShare(nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}
