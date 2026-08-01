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
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outboundproxy"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

var (
	vsockPort      = flag.Uint("vsock-port", 5000, "vsock listening port")
	allowReconfig  = flag.Bool("allow-reconfig", false, "Allow the enclave config to be set multiple times (insecure, for testing only)")
	gatewayTimeout = flag.Duration("gateway-timeout", types.DefaultGatewayRequestTimeout, "Fallback HTTP client timeout for enclave->gateway requests (secrets + capabilities), used when the host injects none. Should not exceed the enclave request timeout.")
)

func main() {
	flag.Parse()
	// Two loggers because the call boundary takes two types: the keychain and
	// the nitro starter want a stdlib *log.Logger, while the confidential-
	// workflows app and its RemoteDispatcher consume chainlink-common's
	// logger.Logger (so the WASM host module gets a single shared instance,
	// see app/app.go). Both default to stderr, so output interleaves cleanly.
	logger := log.New(log.Writer(), "enclave: ", log.LstdFlags|log.Lshortfile)
	appLogger, err := cllogger.New()
	if err != nil {
		logger.Fatalf("Failed to construct chainlink-common logger: %v", err)
	}

	logger.Println("============================================")
	logger.Println("= Starting Confidential Workflows Enclave  =")
	logger.Println("============================================")
	logger.Println()

	att, cleanup, err := nitro.OpenNitroAttestor()
	if err != nil {
		logger.Fatalf("Failed to open Nitro attestor: %v", err)
	}
	defer cleanup()

	kc := keychain.NewBoxKeychain(logger, nil, nil, nil)
	comb := combiner.NewTDH2EasyCombiner()

	// A Nitro EIF is measured (PCR), so environment-specific endpoints cannot be
	// baked in. The gateway URL, storage endpoint, and storage key are all
	// injected by the host at runtime over vsock (see host injectSettings ->
	// app.InjectSettings). This factory builds the remote dispatcher once the
	// gateway URL arrives.
	dispatcherFactory := func(gatewayURL string, timeout time.Duration) (app.RemoteDispatcher, error) {
		if timeout <= 0 {
			timeout = *gatewayTimeout
		}
		// Deliberate narrowing, kept after review: the dialer admits only the
		// configured GATEWAY_URL authorities, so a gateway redirect to a host
		// outside that set fails at dial. The pre-migration client cloned the
		// default transport and followed redirects anywhere, so this would break
		// a CDN front door or a host migration. Kept because it approximates the
		// plan's operator-endpoint profile; revisit if gateway operators need
		// cross-host redirects.
		//
		// What is pinned is the authority, host:port, and not the scheme: the
		// endpoint's scheme only supplies a default port and is then discarded
		// (outboundproxy.endpointAuthority). A redirect that keeps an admitted
		// authority but downgrades https to http still dials, and the parent
		// would then see plaintext. origin/main did not pin the scheme either,
		// so this is not a regression, but it is not covered by this narrowing.
		dialer, err := outboundproxy.NewOperatorDialer(outboundproxy.ParentCID, outboundproxy.Port, gatewayURL)
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

	// Artifact transport is relaxed only by --allow-reconfig, the pre-existing
	// marker for a test EIF. It is a process flag baked in at image build, so it
	// is measured into the PCR and the untrusted host cannot turn it on.
	storageFactory := func(storageURL string, useTLS bool, privateKey string, maxBytes int64, timeout time.Duration, lggr cllogger.Logger) (app.RawFetcher, ed25519.PublicKey, error) {
		operatorDialer, err := outboundproxy.NewOperatorDialer(outboundproxy.ParentCID, outboundproxy.Port, storageURL)
		if err != nil {
			return nil, nil, err
		}
		artifactDialer := outboundproxy.NewArtifactDialer(outboundproxy.ParentCID, outboundproxy.Port)
		var storageOptions = []app.StorageFetcherOption{
			app.WithStorageDialer(operatorDialer.DialContext),
		}
		if *allowReconfig {
			artifactDialer = outboundproxy.NewInsecureArtifactDialerForTests(outboundproxy.ParentCID, outboundproxy.Port)
			storageOptions = append(storageOptions, app.WithInsecureArtifactHTTPDownloadForTests())
		}
		storageOptions = append(storageOptions, app.WithStorageHTTPClient(&http.Client{Transport: tunnelTransport(artifactDialer, false)}))
		return app.NewStorageFetcher(
			storageURL, useTLS, privateKey, maxBytes, timeout, lggr,
			storageOptions...,
		)
	}

	// Cap concurrent executions at (enclave memory - reserve) / per-exec so a burst
	// can't exhaust the fixed enclave memory and wedge the VM. Derived from memory
	// read at startup, so it scales with the enclave's sizing.
	limit := memlimit.Derive()
	appLogger.Infow("Confidential workflows concurrency limit",
		"maxConcurrentExecutions", limit.MaxConcurrent,
		"totalMemMB", limit.TotalMB,
		"reserveMB", limit.ReserveMB,
		"perExecMB", limit.PerExecMB,
		"memoryIntrospected", limit.Introspected,
	)
	appOptions := []app.Option{
		app.WithRemoteDispatcherFactory(dispatcherFactory),
		app.WithStorageFetcherFactory(storageFactory),
		app.WithHTTPFetcher(httpfetch.NewFetcherWithClient(
			httpfetch.DefaultPolicy(),
			util.NewRestrictedHTTPClientWithDialer(
				outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, outboundproxy.Port).DialContext,
			),
		)),
		app.WithMaxConcurrentExecutions(limit.MaxConcurrent),
	}
	if *allowReconfig {
		appOptions = append(appOptions, app.WithInsecureArtifactHTTPForTests())
	}
	confApp := app.NewConfidentialWorkflowsApp(
		sdkpb.TeeType_TEE_TYPE_AWS_NITRO, appLogger, nil,
		appOptions...,
	)

	err = nitro.StartNitroEnclave(
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
		logger.Fatalf("Failed to start Nitro enclave: %v", err)
	}
}

func tunnelTransport(dialer *outboundproxy.Dialer, disableKeepAlives bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// No environment proxy may sit in front of the tunnel. Pinning the plan's
	// invariant: neither EIF Dockerfile sets HTTP_PROXY, HTTPS_PROXY or
	// NO_PROXY, the enclave inherits nothing from the pod, and no injected
	// setting carries one, so dropping ProxyFromEnvironment changes nothing
	// today and keeps a later environment change from reinstating a hop.
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	transport.DisableKeepAlives = disableKeepAlives
	return transport
}
