package main

import (
	"flag"
	"log"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/confidential-compute/enclave/fake/runner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/confidential-compute/types"
)

// This is the fake counterpart of environments/nitro/main.go: it wires the same
// confidential-workflows app but runs it as a local process via the fake runner
// instead of inside a Nitro enclave. Runtime config (gateway/storage endpoints +
// storage key) is injected by the host over vsock, same as nitro, so the fake
// env exercises the production injection path. The keypair-rotation/expiration
// flags mirror the confidential-http fake env so the shared
// build-and-run-fake-enclave.sh harness can drive either app.
var (
	vsockPort         = flag.Uint("vsock-port", 5000, "vsock listening port")
	allowReconfig     = flag.Bool("allow-reconfig", false, "Allow the enclave config to be set multiple times (insecure, for testing only)")
	gatewayTimeout    = flag.Duration("gateway-timeout", types.DefaultGatewayRequestTimeout, "HTTP client timeout for enclave->gateway requests (secrets + capabilities). Should not exceed the enclave request timeout.")
	keypairRotation   = flag.Duration("keypair-rotation", types.DefaultKeypairRotationFrequency, "How often to rotate ephemeral keypairs")
	keypairExpiration = flag.Duration("keypair-expiration", types.DefaultKeypairExpiration, "How long ephemeral keypairs survive before deletion")
)

func main() {
	flag.Parse()
	// Two loggers because the call boundary takes two types: the keychain and
	// the fake runner want a stdlib *log.Logger, while the confidential-workflows
	// app and its RemoteDispatcher consume chainlink-common's logger.Logger.
	logger := log.New(log.Writer(), "enclave: ", log.LstdFlags|log.Lshortfile)
	appLogger, err := cllogger.New()
	if err != nil {
		logger.Fatalf("Failed to construct chainlink-common logger: %v", err)
	}

	logger.Println("=================================================")
	logger.Println("= Starting FAKE Confidential Workflows Enclave  =")
	logger.Println("=================================================")
	logger.Println()

	var rotationOverride *time.Duration
	if *keypairRotation != types.DefaultKeypairRotationFrequency {
		rotationOverride = keypairRotation
	}
	var expirationOverride *time.Duration
	if *keypairExpiration != types.DefaultKeypairExpiration {
		expirationOverride = keypairExpiration
	}

	att, cleanup, err := runner.OpenFakeAttestor()
	if err != nil {
		logger.Fatalf("Failed to open fake attestor: %v", err)
	}
	defer cleanup()

	kc := keychain.NewBoxKeychain(logger, rotationOverride, expirationOverride, nil)
	comb := combiner.NewTDH2EasyCombiner()

	// Runtime config is injected by the host over vsock (see host
	// injectSettings -> app.InjectSettings); the factory builds the remote
	// dispatcher once the gateway URL arrives.
	dispatcherFactory := func(gatewayURL string) app.RemoteDispatcher {
		client := gateway.NewGatewayClient(gatewayURL, att, gateway.WithTimeout(*gatewayTimeout))
		verifier := signatureverifier.NewEd25519SignatureVerifier()
		return app.NewRemoteDispatcher(client, att, types.EnclaveConfig{}, appLogger, kc, comb, verifier)
	}

	err = runner.StartFakeEnclave(
		app.NewConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, appLogger, nil, app.WithRemoteDispatcherFactory(dispatcherFactory)),
		att,
		kc,
		comb,
		logger,
		emitter.NewNoOpEmitter(),
		vsockPort,
		*allowReconfig,
	)
	if err != nil {
		logger.Fatalf("Failed to start fake enclave: %v", err)
	}
}
