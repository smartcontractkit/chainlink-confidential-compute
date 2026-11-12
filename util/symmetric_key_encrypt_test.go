package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Users decrypt encrypted enclave output themselves, so the nonce || ciphertext
// || tag envelope is a public format.
func TestAESGCM_Envelope(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	blob, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaab83761f4124bd679f0d10f3a3720e73e51d19c94349c4b75d40d1b40d7ea7")
	require.NoError(t, err)
	plaintext, err := AESGCMDecrypt(blob, key)
	require.NoError(t, err)
	require.Equal(t, "enclave output", string(plaintext))

	blob, err = AESGCMEncrypt([]byte("enclave output"), key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	require.Len(t, blob, gcm.NonceSize()+len("enclave output")+gcm.Overhead())
	plaintext, err = gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	require.NoError(t, err)
	require.Equal(t, "enclave output", string(plaintext))
}
