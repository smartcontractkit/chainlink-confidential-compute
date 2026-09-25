package keychain

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestWorkerKeyProvisioning(t *testing.T) {
	kc := NewBoxKeychain(log.New(io.Discard, "", 0), nil, nil, nil)
	defer close(kc.stopRotation)
	_, err := kc.CreateKeyPair()
	require.NoError(t, err)
	id := [32]byte{1}
	snapshot, err := SnapshotForRequest(kc, id)
	require.NoError(t, err)
	_, err = kc.CreateKeyPair()
	require.NoError(t, err)
	again, err := SnapshotForRequest(kc, id)
	require.NoError(t, err)
	require.Equal(t, snapshot, again, "rotation must not change a bound request")

	encoded, err := json.Marshal(snapshot)
	require.NoError(t, err)
	var decoded BoxKeySnapshot
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	worker, err := NewRequestKeychain(id, decoded)
	require.NoError(t, err)
	kp, err := worker.GetKeyPairForRequest(id)
	require.NoError(t, err)
	require.True(t, snapshot.CreationTime.Equal(kp.CreationTime()))
	require.Equal(t, snapshot.TTL, kp.TTL())
	ciphertext, err := box.SealAnonymous(nil, []byte("secret"), &snapshot.PublicKey, rand.Reader)
	require.NoError(t, err)
	plaintext, err := kp.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "secret", string(plaintext))
	_, err = worker.GetKeyPairForRequest([32]byte{2})
	require.Error(t, err)
	require.Equal(t, "[private key snapshot]", fmt.Sprintf("%+v", decoded))
	require.Equal(t, "[private key snapshot]", fmt.Sprintf("%#v", decoded))

	decoded.CreationTime = time.Now().Add(-decoded.TTL - time.Second)
	expired, err := NewRequestKeychain(id, decoded)
	require.NoError(t, err)
	kp, err = expired.GetKeyPairForRequest(id)
	require.NoError(t, err)
	_, err = kp.Decrypt(ciphertext)
	require.ErrorContains(t, err, "expired")
	decoded.PublicKey[0] ^= 1
	_, err = NewRequestKeychain(id, decoded)
	require.Error(t, err)
}
