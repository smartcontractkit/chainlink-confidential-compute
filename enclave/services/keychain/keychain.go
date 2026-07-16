// This package provides an interface for managing the enclave's ephemeral key pairs.
// It includes an implementation using nacl/box ed25519 keys.

package keychain

import "time"

type Keypair interface {
	Public() []byte
	Decrypt([]byte) ([]byte, error)
	TTL() time.Duration
	CreationTime() time.Time
}

type Keychain interface {
	CreateKeyPair() (Keypair, error)
	GetKeyPair(publicKey []byte) (Keypair, error)
	GetKeyPairs() ([]Keypair, error)
	// GetKeyPairForRequest returns a single keypair mapped to the given request ID.
	// If no mapping exists, it assigns the newest available keypair to this request ID.
	// This ensures all capability nodes that call this with the same request ID
	// get the same keypair, preventing race conditions during key rotation.
	GetKeyPairForRequest(requestID [32]byte) (Keypair, error)
	DeleteKeyPair(publicKey []byte) error
}
