package keychain

import (
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
)

// BoxKeySnapshot contains private material for an enclave-local worker. It must
// never be exposed through the host API, process arguments, or diagnostics.
type BoxKeySnapshot struct {
	PublicKey    [32]byte      `json:"publicKey"`
	PrivateKey   [32]byte      `json:"privateKey"`
	CreationTime time.Time     `json:"creationTime"`
	TTL          time.Duration `json:"ttl"`
}

func (BoxKeySnapshot) String() string   { return "[private key snapshot]" }
func (BoxKeySnapshot) GoString() string { return "[private key snapshot]" }

// SnapshotForRequest binds through the authoritative keychain before copying
// the selected key. Importing the copy does not renew its expiry.
func SnapshotForRequest(kc Keychain, requestID [32]byte) (*BoxKeySnapshot, error) {
	kp, err := kc.GetKeyPairForRequest(requestID)
	if err != nil {
		return nil, err
	}
	boxKey, ok := kp.(*boxKeypair)
	if !ok {
		return nil, errors.New("keypair does not support worker provisioning")
	}
	return &BoxKeySnapshot{
		PublicKey: boxKey.publicKey, PrivateKey: boxKey.privateKey,
		CreationTime: boxKey.creationTime, TTL: boxKey.ttl,
	}, nil
}

type requestKeychain struct {
	requestID [32]byte
	key       *boxKeypair
}

// NewRequestKeychain imports one request's key without starting rotation.
func NewRequestKeychain(requestID [32]byte, snapshot BoxKeySnapshot) (*requestKeychain, error) {
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &snapshot.PrivateKey)
	if public != snapshot.PublicKey || snapshot.CreationTime.IsZero() || snapshot.TTL <= 0 {
		return nil, errors.New("invalid worker key snapshot")
	}
	return &requestKeychain{requestID: requestID, key: &boxKeypair{
		publicKey: snapshot.PublicKey, privateKey: snapshot.PrivateKey,
		creationTime: snapshot.CreationTime, ttl: snapshot.TTL,
	}}, nil
}

func (k *requestKeychain) GetKeyPairForRequest(id [32]byte) (Keypair, error) {
	if id != k.requestID {
		return nil, errors.New("key is bound to a different request")
	}
	return k.key, nil
}
