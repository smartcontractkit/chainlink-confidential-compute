package keychain

import (
	"errors"
	"io"
	"log"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
)

// failingReader is an io.Reader that always returns an error.
type failingReader struct{}

func (f *failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated entropy failure")
}

func newTestKeychain(reader io.Reader) *boxKeychain {
	exp := 5 * time.Minute
	gcInterval := 30 * time.Second
	return &boxKeychain{
		keypairCache:      util.NewCache[*boxKeypair](&exp, &gcInterval),
		logger:            log.New(io.Discard, "", 0),
		randReader:        reader,
		rotationFrequency: time.Hour, // won't actually tick in these tests
		expiration:        exp,
		stopRotation:      make(chan struct{}),
	}
}

func TestStartKeyRotation_PanicsOnInitialKeypairFailure(t *testing.T) {
	t.Parallel()

	kc := newTestKeychain(&failingReader{})

	assert.PanicsWithValue(t,
		"keychain: failed to create initial keypair: failed to generate keypair: simulated entropy failure",
		func() { kc.startKeyRotation() },
	)
}

func TestStartKeyRotation_PanicsOnRotationKeypairFailure(t *testing.T) {
	t.Parallel()

	exp := 5 * time.Minute
	gcInterval := 30 * time.Second
	kc := &boxKeychain{
		keypairCache:      util.NewCache[*boxKeypair](&exp, &gcInterval),
		logger:            log.New(io.Discard, "", 0),
		randReader:        &limitedReader{remaining: 32}, // enough for initial keypair only
		rotationFrequency: time.Millisecond,              // fires quickly so rotation attempt happens
		expiration:        exp,
		stopRotation:      make(chan struct{}),
	}

	assert.PanicsWithValue(t,
		"keychain: failed to rotate keypair: failed to generate keypair: simulated entropy failure",
		func() { kc.startKeyRotation() },
	)
}

// limitedReader succeeds for the first `remaining` bytes, then fails.
type limitedReader struct {
	remaining int
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("simulated entropy failure")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	// Fill with deterministic bytes for key generation
	for i := range n {
		p[i] = byte(i)
	}
	r.remaining -= n
	return n, nil
}
