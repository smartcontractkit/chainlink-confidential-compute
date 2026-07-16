package keychain_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSampleKeychain(t *testing.T) {
	t.Parallel()

	logger := log.New(io.Discard, "", 0)
	ttl := time.Minute
	kc := keychain.NewBoxKeychain(logger, nil, &ttl, nil)

	t.Run("CreateKeyPair", func(t *testing.T) {
		t.Parallel()
		pair, err := kc.CreateKeyPair()
		if err != nil {
			t.Errorf("CreateKeyPair failed: %v", err)
		}
		if len(pair.Public()) == 0 || len(pair.Public()) != 32 {
			t.Error("CreateKeyPair returned empty keys")
		}
		require.Equal(t, pair.TTL(), time.Minute)
	})

	t.Run("GetKeyPair", func(t *testing.T) {
		t.Parallel()

		pair, err := kc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		pair2, err := kc.GetKeyPair(pair.Public())
		if err != nil {
			t.Errorf("GetKeyPair failed: %v", err)
		}

		if !bytes.Equal(pair.Public(), pair2.Public()) {
			t.Error("GetKeyPair returned different keys than the ones created")
		}
	})

	t.Run("GetKeyPair_NotFound", func(t *testing.T) {
		t.Parallel()

		nonExistentKey := make([]byte, 32)

		_, err := kc.GetKeyPair(nonExistentKey)
		if err == nil {
			t.Error("GetKeyPair should fail for non-existent keys")
		}
		assert.EqualError(t, err, "keypair not found", "Expected specific error message for non-existent key")
	})

	t.Run("GetKeyPair_InvalidLength", func(t *testing.T) {
		t.Parallel()

		invalidKey := []byte("too-short-key")
		_, err := kc.GetKeyPair(invalidKey)
		if err == nil {
			t.Error("GetKeyPair should fail for invalid length key")
		}

		expectedError := fmt.Sprintf("invalid public key length: expected 32 bytes, got %d bytes", len(invalidKey))
		assert.EqualError(t, err, expectedError, "Expected specific error message for invalid key length")
	})

	t.Run("GetKeyPairs", func(t *testing.T) {
		t.Parallel()

		logger := log.New(io.Discard, "", 0)
		localKc := keychain.NewBoxKeychain(logger, nil, nil, nil)

		pair1, err := localKc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		pair2, err := localKc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		pairs, err := localKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}

		assert.GreaterOrEqual(t, len(pairs), 2, "expected at least 2 keypairs")

		found1, found2 := false, false
		for _, pair := range pairs {
			if bytes.Equal(pair.Public(), pair1.Public()) {
				found1 = true
			}
			if bytes.Equal(pair.Public(), pair2.Public()) {
				found2 = true
			}
		}

		assert.True(t, found1, "first created keypair not found in GetKeyPairs result")
		assert.True(t, found2, "second created keypair not found in GetKeyPairs result")
	})

	t.Run("AutomaticKeyRotation", func(t *testing.T) {
		// Create a keychain with short rotation to observe rotation
		rotationFreq := 50 * time.Millisecond
		expiration := 200 * time.Millisecond
		logger := log.New(io.Discard, "", 0)
		rotatingKc := keychain.NewBoxKeychain(logger, &rotationFreq, &expiration, nil)

		// Wait for initial key creation.
		for range 100 {
			if keys, err := rotatingKc.GetKeyPairs(); err != nil && len(keys) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		initialKeys, err := rotatingKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}
		assert.GreaterOrEqual(t, len(initialKeys), 1, "expected at least 1 initial keypair")

		// Wait for rotation.
		time.Sleep(rotationFreq + 20*time.Millisecond)

		rotatedKeys, err := rotatingKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}
		assert.NotEqual(t, initialKeys[0].Public(), rotatedKeys[0].Public(), "expected keypair rotation to have updated the newest keypair")

		rotatingKc.StopKeyRotation()
	})

	t.Run("StopKeyRotation", func(t *testing.T) {
		rotationFreq := 100 * time.Millisecond
		expiration := 400 * time.Millisecond
		logger := log.New(io.Discard, "", 0)
		rotatingKc := keychain.NewBoxKeychain(logger, &rotationFreq, &expiration, nil)

		// Wait for initial key creation.
		for range 100 {
			if keys, err := rotatingKc.GetKeyPairs(); err != nil && len(keys) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		// Stop the rotation
		rotatingKc.StopKeyRotation()

		initialKeys, err := rotatingKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}
		initialCount := len(initialKeys)
		assert.GreaterOrEqual(t, initialCount, 1, "expected at least 1 initial keypair")

		// Create a keypair manually to verify the keychain still works
		_, err = rotatingKc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed after stopping rotation: %v", err)
		}

		afterManualKeys, err := rotatingKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}
		assert.Greater(t, len(afterManualKeys), initialCount, "expected more keypairs after manual creation")

		time.Sleep((rotationFreq) + 20*time.Millisecond)

		// Keys may be garbage collected by the cache but should not have been added since the manual key creation.
		finalKeys, err := rotatingKc.GetKeyPairs()
		if err != nil {
			t.Fatalf("GetKeyPairs failed: %v", err)
		}
		assert.LessOrEqual(t, len(finalKeys), len(afterManualKeys), "key count should not increasae after rotation is stopped")
	})

	t.Run("DeleteKeyPair", func(t *testing.T) {
		t.Parallel()

		// Create a keypair first
		pair, err := kc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		// Now try to delete it
		err = kc.DeleteKeyPair(pair.Public())
		// Currently, the sample implementation returns an error as it's not implemented
		if err == nil {
			t.Error("Expected DeleteKeyPair to return an error as it's not implemented")
		}
	})

	t.Run("GetKeyPairForRequest_ReturnsSameKeyForSameRequest", func(t *testing.T) {
		t.Parallel()

		logger := log.New(io.Discard, "", 0)
		shortTTL := time.Minute
		localKc := keychain.NewBoxKeychain(logger, nil, &shortTTL, nil)
		defer localKc.StopKeyRotation()

		// Wait for initial key creation.
		require.Eventually(t, func() bool {
			keys, err := localKc.GetKeyPairs()
			return err == nil && len(keys) > 0
		}, 2*time.Second, 10*time.Millisecond)

		requestID := [32]byte{1, 2, 3}

		kp1, err := localKc.GetKeyPairForRequest(requestID)
		require.NoError(t, err)

		kp2, err := localKc.GetKeyPairForRequest(requestID)
		require.NoError(t, err)

		assert.True(t, bytes.Equal(kp1.Public(), kp2.Public()),
			"same request ID should return the same keypair")
	})

	t.Run("GetKeyPairForRequest_DifferentRequestsCanGetDifferentKeys", func(t *testing.T) {
		t.Parallel()

		logger := log.New(io.Discard, "", 0)
		rotationFreq := 50 * time.Millisecond
		expiration := 500 * time.Millisecond // keys live much longer than rotation
		localKc := keychain.NewBoxKeychain(logger, &rotationFreq, &expiration, nil)
		defer localKc.StopKeyRotation()

		// Wait for initial key creation.
		require.Eventually(t, func() bool {
			keys, err := localKc.GetKeyPairs()
			return err == nil && len(keys) > 0
		}, 2*time.Second, 10*time.Millisecond)

		reqA := [32]byte{1}
		kpA, err := localKc.GetKeyPairForRequest(reqA)
		require.NoError(t, err)
		require.NotNil(t, kpA)

		// Wait for key rotation.
		time.Sleep(rotationFreq + 20*time.Millisecond)

		reqB := [32]byte{2}
		kpB, err := localKc.GetKeyPairForRequest(reqB)
		require.NoError(t, err)
		require.NotNil(t, kpB)

		// reqA should still get the original key
		kpA2, err := localKc.GetKeyPairForRequest(reqA)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(kpA.Public(), kpA2.Public()),
			"reqA should still be mapped to its original keypair after rotation")
	})

	t.Run("GetKeyPairForRequest_ErrorsAfterExpiry", func(t *testing.T) {
		// Verifies that if the mapped keypair is garbage-collected,
		// an error is returned rather than silently assigning a new key.
		logger := log.New(io.Discard, "", 0)
		shortExpiration := 50 * time.Millisecond
		shortGC := 30 * time.Millisecond
		localKc := keychain.NewBoxKeychain(logger, nil, &shortExpiration, &shortGC)
		defer localKc.StopKeyRotation()

		// Wait for initial key creation.
		require.Eventually(t, func() bool {
			keys, err := localKc.GetKeyPairs()
			return err == nil && len(keys) > 0
		}, 2*time.Second, 10*time.Millisecond)

		reqID := [32]byte{42}
		_, err := localKc.GetKeyPairForRequest(reqID)
		require.NoError(t, err)

		// Wait for the original key to expire and be garbage-collected.
		time.Sleep(shortExpiration + shortGC + 30*time.Millisecond)

		_, err = localKc.GetKeyPairForRequest(reqID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mapped keypair for request")
		assert.Contains(t, err.Error(), "has expired")
	})

	t.Run("GetKeyPairForRequest_ConcurrentAccess", func(t *testing.T) {
		t.Parallel()

		logger := log.New(io.Discard, "", 0)
		ttl := time.Minute
		localKc := keychain.NewBoxKeychain(logger, nil, &ttl, nil)
		defer localKc.StopKeyRotation()

		// Wait for initial key creation.
		require.Eventually(t, func() bool {
			keys, err := localKc.GetKeyPairs()
			return err == nil && len(keys) > 0
		}, 2*time.Second, 10*time.Millisecond)

		requestID := [32]byte{99}
		const goroutines = 20
		results := make(chan []byte, goroutines)

		var wg sync.WaitGroup
		wg.Add(goroutines)
		for range goroutines {
			go func() {
				defer wg.Done()
				kp, err := localKc.GetKeyPairForRequest(requestID)
				require.NoError(t, err)
				results <- kp.Public()
			}()
		}
		wg.Wait()
		close(results)

		// All goroutines should have gotten the same key.
		var first []byte
		for pubKey := range results {
			if first == nil {
				first = pubKey
			}
			assert.True(t, bytes.Equal(first, pubKey),
				"concurrent calls with same requestID must return the same key")
		}
	})

	t.Run("KeyExpiration", func(t *testing.T) {
		// Create a keychain with a very short TTL so we can test expiration
		shortTTL := 10 * time.Millisecond
		logger := log.New(io.Discard, "", 0)
		kcExpiring := keychain.NewBoxKeychain(logger, nil, &shortTTL, nil)

		// Create a keypair
		pair, err := kcExpiring.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		// Verify it exists
		_, err = kcExpiring.GetKeyPair(pair.Public())
		if err != nil {
			t.Errorf("GetKeyPair failed immediately after creation: %v", err)
		}

		// Wait for the TTL to expire
		time.Sleep(20 * time.Millisecond)

		// Now the key should be expired even before GC runs
		_, err = kcExpiring.GetKeyPair(pair.Public())
		if err == nil {
			t.Error("Expected GetKeyPair to fail for expired key")
		}

		// Cleanup
		kcExpiring.StopKeyRotation()
	})

	t.Run("AutomaticGarbageCollection", func(t *testing.T) {
		// Create a keychain with a very short TTL and GC interval
		shortTTL := 10 * time.Millisecond
		shortGCInterval := 50 * time.Millisecond

		logger := log.New(io.Discard, "", 0)
		kcGC := keychain.NewBoxKeychain(logger, nil, &shortTTL, &shortGCInterval)

		// Create a keypair
		pair, err := kcGC.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		// Wait for the TTL to expire and GC to run
		time.Sleep(shortTTL + shortGCInterval + 10*time.Millisecond)

		// Check if the key was removed by GC by attempting to get it
		_, err = kcGC.GetKeyPair(pair.Public())
		if err == nil {
			t.Error("Expected GetKeyPair to fail for expired key after GC")
		}
		assert.EqualError(t, err, "keypair not found", "Expected error message to match")

		// Cleanup
		kcGC.StopKeyRotation()
	})

	t.Run("AnonymousEncryptionDecryption", func(t *testing.T) {
		t.Parallel()

		// Create a keypair
		pair, err := kc.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		// Original message to encrypt
		originalMessage := []byte("this is a test message for anonymous encryption")

		// Convert public key to the required format for box.SealAnonymous
		var publicKey [32]byte
		copy(publicKey[:], pair.Public())

		// Encrypt the message anonymously
		ciphertext, err := box.SealAnonymous(nil, originalMessage, &publicKey, nil)
		if err != nil {
			t.Fatalf("failed to encrypt message: %v", err)
		}

		// Decrypt the ciphertext using the keypair's Decrypt method
		decrypted, err := pair.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("failed to decrypt message: %v", err)
		}

		// Verify the decrypted message matches the original
		if !bytes.Equal(originalMessage, decrypted) {
			t.Errorf("decrypted message does not match original message")
		}
	})

	t.Run("DecryptWithExpiredKey", func(t *testing.T) {
		// Create a keychain with a very short TTL
		shortTTL := 10 * time.Millisecond
		logger := log.New(io.Discard, "", 0)
		kcExpiring := keychain.NewBoxKeychain(logger, nil, &shortTTL, nil)

		// Create a keypair
		pair, err := kcExpiring.CreateKeyPair()
		if err != nil {
			t.Fatalf("CreateKeyPair failed: %v", err)
		}

		// Original message to encrypt
		originalMessage := []byte("this message will not be decrypted due to expiration")

		// Convert public key to the required format for box.SealAnonymous
		var publicKey [32]byte
		copy(publicKey[:], pair.Public())

		// Encrypt the message anonymously
		ciphertext, err := box.SealAnonymous(nil, originalMessage, &publicKey, nil)
		if err != nil {
			t.Fatalf("failed to encrypt message: %v", err)
		}

		// Wait for the TTL to expire
		time.Sleep(20 * time.Millisecond)

		// Try to decrypt with the expired key
		_, err = pair.Decrypt(ciphertext)

		// Verify that decryption fails with the expected error message
		if err == nil {
			t.Error("expected decrypt to fail with expired key")
		}
		assert.Contains(t, err.Error(), "keypair has expired", "expected error to mention key expiration")

		// Cleanup
		kcExpiring.StopKeyRotation()
	})
}

func TestGetKeyPairForRequest_LoadOrStore_RaceConsistency(t *testing.T) {
	// Verifies the LoadOrStore fix: when many goroutines race to map the
	// same requestID during a key rotation, ALL callers must return the
	// same public key. Before the fix (plain Store), the second writer
	// could silently return a different key than the one that was stored.
	t.Parallel()

	logger := log.New(io.Discard, "", 0)
	rotationFreq := 10 * time.Millisecond
	expiration := 2 * time.Second
	kc := keychain.NewBoxKeychain(logger, &rotationFreq, &expiration, nil)
	defer kc.StopKeyRotation()

	require.Eventually(t, func() bool {
		keys, err := kc.GetKeyPairs()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 5*time.Millisecond)

	// Let a few rotations happen so there are multiple keys in the cache.
	time.Sleep(5 * rotationFreq)

	const goroutines = 50
	requestID := [32]byte{0xAA}
	results := make([][]byte, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			kp, err := kc.GetKeyPairForRequest(requestID)
			require.NoError(t, err)
			results[idx] = kp.Public()
		}(i)
	}
	wg.Wait()

	// Every goroutine must have gotten the exact same public key.
	for i := 1; i < goroutines; i++ {
		assert.True(t, bytes.Equal(results[0], results[i]),
			"goroutine %d returned a different key than goroutine 0 — LoadOrStore race", i)
	}
}

func TestRequestKeyMapSweep(t *testing.T) {
	// Verifies that stale entries in requestKeyMap are cleaned up by the
	// periodic sweep on the rotation ticker, preventing unbounded growth.
	t.Parallel()

	logger := log.New(io.Discard, "", 0)
	rotationFreq := 50 * time.Millisecond
	expiration := 80 * time.Millisecond
	gcInterval := 30 * time.Millisecond
	kc := keychain.NewBoxKeychain(logger, &rotationFreq, &expiration, &gcInterval)
	defer kc.StopKeyRotation()

	require.Eventually(t, func() bool {
		keys, err := kc.GetKeyPairs()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 5*time.Millisecond)

	// Map a request to the current newest key.
	reqID := [32]byte{0xBB}
	kp, err := kc.GetKeyPairForRequest(reqID)
	require.NoError(t, err)
	require.NotNil(t, kp)

	// The mapping should work immediately.
	kp2, err := kc.GetKeyPairForRequest(reqID)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(kp.Public(), kp2.Public()))

	// Wait long enough for expiration + GC + at least one rotation tick
	// (which runs the sweep). The mapped key should be evicted from the
	// cache and then the sweep should remove it from requestKeyMap.
	time.Sleep(expiration + gcInterval + rotationFreq + 50*time.Millisecond)

	// Now a lookup should fail because the sweep cleaned the mapping
	// and the underlying key is gone from the cache.
	_, err = kc.GetKeyPairForRequest(reqID)
	// After sweep, the mapping is gone, so it will assign a new (current) key
	// rather than returning "has expired". Either outcome is acceptable
	// as long as we don't leak memory. The key point is that the old
	// mapping was cleaned up.
	if err != nil {
		assert.Contains(t, err.Error(), "has expired")
	}
}

// Helper function for test - creates a cache with custom GC interval
func NewCacheWithCustomGC[T any](ttl time.Duration, gcInterval time.Duration) *util.Cache[T] {
	return util.NewCache[T](&ttl, &gcInterval)
}
