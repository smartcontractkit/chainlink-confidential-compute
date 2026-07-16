// Sample KeyChain implementation that generates random NaCl/box keypairs.

package keychain

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"golang.org/x/crypto/nacl/box"
)

var (
	defaultRotationFrequency  = types.DefaultKeypairRotationFrequency
	defaultExpiration         = types.DefaultKeypairExpiration
	garbageCollectionInterval = 30 * time.Second
	// requestKeyMapTTL expires requestID->keypair mappings long after any
	// in-flight request could still need them.
	requestKeyMapTTL = 1 * time.Hour
)

// boxKeypair represents a keypair for NaCl/box encryption.
// Its contents should never leave the enclave.
type boxKeypair struct {
	publicKey    [32]byte
	privateKey   [32]byte
	ttl          time.Duration
	creationTime time.Time
}

var _ Keypair = (*boxKeypair)(nil)

func (kp *boxKeypair) Public() []byte {
	return kp.publicKey[:]
}

func (kp *boxKeypair) Decrypt(ciphertext []byte) ([]byte, error) {
	if kp.creationTime.Add(kp.ttl).Before(time.Now()) {
		return nil, fmt.Errorf("keypair has expired: %dms old, TTL: %dms",
			time.Since(kp.creationTime).Milliseconds(),
			kp.ttl.Milliseconds())
	}

	var publicKey [32]byte
	copy(publicKey[:], kp.publicKey[:])

	var privateKey [32]byte
	copy(privateKey[:], kp.privateKey[:])

	decrypted, ok := box.OpenAnonymous(nil, ciphertext, &publicKey, &privateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return decrypted, nil
}

func (kp *boxKeypair) TTL() time.Duration {
	return kp.ttl
}

func (kp *boxKeypair) CreationTime() time.Time {
	return kp.creationTime
}

type boxKeychain struct {
	keypairCache      *util.Cache[*boxKeypair]
	requestKeyMap     *util.Cache[[32]byte] // bounded map: requestID -> keypair publicKey
	logger            *log.Logger
	randReader        io.Reader
	rotationFrequency time.Duration
	expiration        time.Duration
	stopRotation      chan struct{}
}

var _ Keychain = (*boxKeychain)(nil)

// NewBoxKeychain creates a new keychain instance using NaCl/box keys.
// rotationFrequency controls how often a new keypair is generated.
// expiration controls how long old keypairs stick around before deletion.
// This decoupling ensures laggard requests can still use older keys
// that have been rotated out but not yet expired.
func NewBoxKeychain(
	logger *log.Logger,
	rotationFrequencyOverride *time.Duration,
	expirationOverride *time.Duration,
	gcIntervalOverride *time.Duration,
) *boxKeychain {
	rotFreq := defaultRotationFrequency
	if rotationFrequencyOverride != nil {
		rotFreq = *rotationFrequencyOverride
	}
	exp := defaultExpiration
	if expirationOverride != nil {
		exp = *expirationOverride
	}
	gcInterval := garbageCollectionInterval
	if gcIntervalOverride != nil {
		gcInterval = *gcIntervalOverride
	}

	keychain := &boxKeychain{
		keypairCache:      util.NewCache[*boxKeypair](&exp, &gcInterval),
		requestKeyMap:     util.NewBoundedCache[[32]byte](&requestKeyMapTTL, &gcInterval, types.MaxRequestKeyMapEntries),
		logger:            logger,
		randReader:        rand.Reader,
		rotationFrequency: rotFreq,
		expiration:        exp,
		stopRotation:      make(chan struct{}),
	}

	go keychain.startKeyRotation()

	return keychain
}

// CreateKeyPair generates a new keypair and stores it in the keychain's cache.
func (skc *boxKeychain) CreateKeyPair() (Keypair, error) {
	newKey, err := skc.generateKeypair()
	if err != nil {
		return nil, err
	}

	keyID := skc.getKeyID(newKey.Public())
	skc.keypairCache.Set(keyID, newKey, nil)

	return newKey, nil
}

// GetKeyPair retrieves a keypair by its public key. If the keypair does not exist, it returns an error.
func (skc *boxKeychain) GetKeyPair(publickey []byte) (Keypair, error) {
	if len(publickey) != 32 {
		return nil, fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publickey))
	}

	keyID := skc.getKeyID(publickey)
	key, exists := skc.keypairCache.Get(keyID)
	if !exists {
		return nil, fmt.Errorf("keypair not found")
	}

	return key, nil
}

func (skc *boxKeychain) GetKeyPairs() ([]Keypair, error) {
	keys := skc.keypairCache.Keys()
	keypairs := make([]Keypair, 0, len(keys))

	for _, key := range keys {
		keypair, exists := skc.keypairCache.Get(key)
		if exists {
			keypairs = append(keypairs, keypair)
		}
	}

	return keypairs, nil
}

// GetKeyPairForRequest returns a single keypair mapped to the given request ID.
// If no mapping exists yet, it assigns the newest available keypair.
// If the mapped keypair has been garbage-collected (expired), it returns an error.
// Uses GetOrSet to avoid a TOCTOU race where two goroutines could both
// miss the Get, pick different keys after a rotation, and silently diverge.
func (skc *boxKeychain) GetKeyPairForRequest(requestID [32]byte) (Keypair, error) {
	// Check if we already have a mapping for this request ID.
	if keyID, ok := skc.requestKeyMap.Get(requestID); ok {
		if kp, exists := skc.keypairCache.Get(keyID); exists {
			return kp, nil
		}
		// Mapped keypair was garbage-collected; the request took too long.
		skc.requestKeyMap.Delete(requestID)
		return nil, fmt.Errorf("mapped keypair for request %x has expired", requestID)
	}

	// No existing mapping — find the newest keypair.
	keypairs, err := skc.GetKeyPairs()
	if err != nil {
		return nil, err
	}
	if len(keypairs) == 0 {
		return nil, fmt.Errorf("no keypairs available")
	}

	var newest Keypair
	for _, kp := range keypairs {
		if newest == nil || kp.CreationTime().After(newest.CreationTime()) {
			newest = kp
		}
	}

	// GetOrSet ensures the first writer wins. If another goroutine raced us
	// and stored a different key, we use theirs to maintain the invariant that
	// every caller for the same requestID gets the same keypair.
	pubKeyArr := skc.getKeyID(newest.Public())
	keyID, loaded := skc.requestKeyMap.GetOrSet(requestID, pubKeyArr, nil)
	if loaded {
		// Another goroutine stored first — use their key.
		if kp, exists := skc.keypairCache.Get(keyID); exists {
			return kp, nil
		}
		skc.requestKeyMap.Delete(requestID)
		return nil, fmt.Errorf("mapped keypair for request %x has expired", requestID)
	}

	return newest, nil
}

func (skc *boxKeychain) DeleteKeyPair(publicKey []byte) error {
	return fmt.Errorf("delete keypair not implemented")
}

func (skc *boxKeychain) generateKeypair() (*boxKeypair, error) {
	publicKey, privateKey, err := box.GenerateKey(skc.randReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	return &boxKeypair{
		publicKey:    *publicKey,
		privateKey:   *privateKey,
		ttl:          skc.expiration,
		creationTime: time.Now(),
	}, nil
}

func (skc *boxKeychain) getKeyID(publicKey []byte) [32]byte {
	return [32]byte(publicKey)
}

// startKeyRotation creates new keypairs at the configured rotation frequency
// and periodically sweeps stale entries from requestKeyMap.
func (skc *boxKeychain) startKeyRotation() {
	ticker := time.NewTicker(skc.rotationFrequency)
	defer ticker.Stop()

	if _, err := skc.CreateKeyPair(); err != nil {
		panic(fmt.Sprintf("keychain: failed to create initial keypair: %v", err))
	}

	for {
		select {
		case <-ticker.C:
			if _, err := skc.CreateKeyPair(); err != nil {
				panic(fmt.Sprintf("keychain: failed to rotate keypair: %v", err))
			}
			skc.sweepRequestKeyMap()
		case <-skc.stopRotation:
			return
		}
	}
}

// sweepRequestKeyMap removes entries from requestKeyMap whose mapped keypair
// is no longer present in the cache (i.e. has expired).
func (skc *boxKeychain) sweepRequestKeyMap() {
	for _, requestID := range skc.requestKeyMap.Keys() {
		if publicKey, ok := skc.requestKeyMap.Get(requestID); ok {
			if _, exists := skc.keypairCache.Get(publicKey); !exists {
				skc.requestKeyMap.Delete(requestID)
			}
		}
	}
}

func (skc *boxKeychain) StopKeyRotation() {
	close(skc.stopRotation)
}
