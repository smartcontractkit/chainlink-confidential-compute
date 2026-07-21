package main

import (
	"flag"
	"log"
	"time"

	"github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-http/app"
	"github.com/smartcontractkit/confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/confidential-compute/types"
)

var (
	vsockPort         = flag.Uint("vsock-port", 5000, "vsock listening port")
	keypairRotation   = flag.Duration("keypair-rotation", types.DefaultKeypairRotationFrequency, "How often to rotate ephemeral keypairs")
	keypairExpiration = flag.Duration("keypair-expiration", types.DefaultKeypairExpiration, "How long ephemeral keypairs survive before deletion")
	allowReconfig     = flag.Bool("allow-reconfig", false, "Allow the enclave config to be set multiple times (insecure, for testing only)")
)

func main() {
	flag.Parse()
	logger := log.New(log.Writer(), "enclave: ", log.LstdFlags|log.Lshortfile)

	var rotationOverride *time.Duration
	if *keypairRotation != types.DefaultKeypairRotationFrequency {
		rotationOverride = keypairRotation
	}
	var expirationOverride *time.Duration
	if *keypairExpiration != types.DefaultKeypairExpiration {
		expirationOverride = keypairExpiration
	}

	att, cleanup, err := nitro.OpenNitroAttestor()
	if err != nil {
		logger.Fatalf("Failed to open Nitro attestor: %v", err)
	}
	defer cleanup()

	err = nitro.StartNitroEnclave(
		app.NewHTTPEnclaveApp(nil),
		att,
		keychain.NewBoxKeychain(logger, rotationOverride, expirationOverride, nil),
		combiner.NewTDH2EasyCombiner(),
		logger,
		emitter.NewNoOpEmitter(),
		vsockPort,
		*allowReconfig,
	)
	if err != nil {
		logger.Fatalf("Failed to start Nitro enclave: %v", err)
	}
}
