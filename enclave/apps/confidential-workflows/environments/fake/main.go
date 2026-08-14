package main

import (
	"crypto/ed25519"
	"flag"
	"log"
	"net/http"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/fake/runner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
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
	gatewayTimeout    = flag.Duration("gateway-timeout", types.DefaultGatewayRequestTimeout, "Fallback HTTP client timeout for enclave->gateway requests (secrets + capabilities), used when the host injects none. Should not exceed the enclave request timeout.")
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
	dispatcherFactory := func(gatewayURL string, timeout time.Duration) (app.RemoteDispatcher, error) {
		if timeout <= 0 {
			timeout = *gatewayTimeout
		}
		dialer, err := proxyclient.NewConfiguredEndpointDialer(types.ProxyParentCID, types.ProxyPort, gatewayURL)
		if err != nil {
			return nil, err
		}
		client := gateway.NewGatewayClient(gatewayURL, att, gateway.WithHTTPClient(&http.Client{
			Timeout:   timeout,
			Transport: tunnelTransport(dialer, true),
		}))
		verifier := signatureverifier.NewEd25519SignatureVerifier()
		return app.NewRemoteDispatcher(client, att, types.EnclaveConfig{}, appLogger, kc, comb, verifier), nil
	}

	storageFactory := func(storageURL string, useTLS bool, privateKey string, maxBytes int64, timeout time.Duration, lggr cllogger.Logger) (app.RawFetcher, ed25519.PublicKey, error) {
		operatorDialer, err := proxyclient.NewConfiguredEndpointDialer(types.ProxyParentCID, types.ProxyPort, storageURL)
		if err != nil {
			return nil, nil, err
		}
		artifactDialer := proxyclient.NewPreSignedURLDialer(types.ProxyParentCID, types.ProxyPort)
		var artifactClient types.HTTPClient = util.NewRestrictedHTTPClientWithDialer(artifactDialer.DialContext)
		if *allowReconfig {
			artifactDialer = proxyclient.NewInsecureFixtureDialerForTests(types.ProxyParentCID, types.ProxyPort)
			artifactClient = &http.Client{Transport: tunnelTransport(artifactDialer, false)}
		}
		return app.NewStorageFetcher(
			storageURL, useTLS, privateKey, maxBytes, timeout, lggr, artifactClient,
			app.WithStorageDialer(operatorDialer.DialContext),
		)
	}

	confApp, err := app.NewConfidentialWorkflowsApp(
		sdkpb.TeeType_TEE_TYPE_AWS_NITRO,
		appLogger,
		app.Config{
			RemoteDispatcherFactory: dispatcherFactory,
			StorageFetcherFactory:   storageFactory,
			HTTPFetcher: httpfetch.NewFetcherWithClient(
				httpfetch.DefaultPolicy(),
				util.NewRestrictedHTTPClientWithDialer(
					proxyclient.NewWorkflowControlledDialer(types.ProxyParentCID, types.ProxyPort).DialContext,
				),
			),
		},
	)
	if err != nil {
		logger.Fatalf("Failed to construct confidential workflows app: %v", err)
	}

	err = runner.StartFakeEnclave(
		confApp,
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

func tunnelTransport(dialer *proxyclient.Dialer, disableKeepAlives bool) *http.Transport {
	return &http.Transport{
		DialContext:       dialer.DialContext,
		DisableKeepAlives: disableKeepAlives,
		ForceAttemptHTTP2: true,
	}
}
