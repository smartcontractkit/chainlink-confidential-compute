// Package runner contains the fake enclave runtime: it wires the shared enclave
// server, sidecars, and vsock abstraction to run an enclave app locally without
// Nitro hardware. It is intentionally separate from package fake so that
// attestation primitives (fake.ValidateAttestation, fake.FakeAttestor) stay
// lightweight and importable by the client without pulling in the enclave
// server stack.
package runner

import (
	"log"
	"math"
	"net"

	"github.com/smartcontractkit/confidential-compute/enclave/fake"
	"github.com/smartcontractkit/confidential-compute/enclave/server"
	"github.com/smartcontractkit/confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/confidential-compute/types"
)

// OpenFakeAttestor returns a FakeAttestor and a dummy cleanup function.
func OpenFakeAttestor() (attestor.Attestor, func(), error) {
	return &fake.FakeAttestor{}, func() {}, nil
}

// StartFakeEnclave starts the enclave server using the fake environment without Nitro-specific checks.
func StartFakeEnclave(
	app types.EnclaveApp,
	att attestor.Attestor,
	keychain keychain.Keychain,
	combiner combiner.Combiner,
	logger *log.Logger,
	emitter types.Emitter,
	vsockPort *uint,
	allowReconfig bool,
) error {
	if *vsockPort > math.MaxUint32 {
		logger.Fatalf("Invalid port")
	}

	// Instantiate a new enclave server.
	verifier := signatureverifier.NewEd25519SignatureVerifier()
	server := server.NewEnclaveServer(
		app,
		att,
		logger,
		keychain,
		verifier,
		combiner,
		emitter,
		types.EnclaveConfig{},
		allowReconfig,
	)

	// Start the server using the vsock abstraction.
	var listener net.Listener
	listener, err := vsock.Listen(uint32(*vsockPort), nil)
	if err != nil {
		logger.Fatalf("cannot listen on vsock: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return server.Start(listener)
}
