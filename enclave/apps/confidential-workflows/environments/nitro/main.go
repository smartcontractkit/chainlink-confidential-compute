package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/nitrotransport"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
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
	processes, err := worker.NewProcesses("/usr/bin/workflow-worker", nil, nil, kc, appLogger)
	if err != nil {
		logger.Fatalf("Failed to configure worker: %v", err)
	}
	defer processes.Close()

	// A Nitro EIF is measured (PCR), so environment-specific endpoints cannot be
	// baked in. The gateway URL, storage endpoint, and storage key are all
	// injected by the host at runtime over vsock (see host injectSettings ->
	// app.InjectSettings). This factory builds the remote dispatcher once the
	// gateway URL arrives.
	dispatcherFactory := func(gw app.GatewayConfig) (app.RemoteDispatcher, error) {
		if gw.RequestTimeout <= 0 {
			gw.RequestTimeout = *gatewayTimeout
		}
		return nitrotransport.Dispatcher(gw, types.EnclaveConfig{}, att, kc, appLogger, 0)
	}

	// allow-reconfig is measured into the PCR, so the host cannot enable the fixture profile.
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

	// Admission budgets for cold workers but does not enforce a native RSS limit.
	limit := memlimit.Derive()
	appLogger.Infow("Confidential workflows concurrency limit",
		"maxConcurrentExecutions", limit.MaxConcurrent,
		"totalMemMB", limit.TotalMB,
		"reserveMB", limit.ReserveMB,
		"perExecMB", limit.PerExecMB,
		"memoryIntrospected", limit.Introspected,
	)
	confApp, err := app.NewConfidentialWorkflowsApp(
		sdkpb.TeeType_TEE_TYPE_AWS_NITRO,
		appLogger,
		app.Config{
			Worker:                  processes,
			GatewayTimeout:          *gatewayTimeout,
			RemoteDispatcherFactory: dispatcherFactory,
			StorageFetcherFactory:   storageFactory,
			HTTPFetcher:             nitrotransport.HTTPFetcher(0),
			MaxConcurrentExecutions: limit.MaxConcurrent,
		},
	)
	if err != nil {
		logger.Fatalf("Failed to construct confidential workflows app: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		done <- nitro.StartNitroEnclave(
			confApp,
			att,
			kc,
			comb,
			logger,
			emitter.NewNoOpEmitter(),
			vsockPort,
			*allowReconfig,
		)
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
	}
	if err != nil {
		_ = processes.Close()
		logger.Fatalf("Nitro enclave stopped: %v", err)
	}
}

func tunnelTransport(dialer *proxyclient.Dialer, disableKeepAlives bool) *http.Transport {
	return &http.Transport{
		DialContext:       dialer.DialContext,
		DisableKeepAlives: disableKeepAlives,
		ForceAttemptHTTP2: true,
	}
}
