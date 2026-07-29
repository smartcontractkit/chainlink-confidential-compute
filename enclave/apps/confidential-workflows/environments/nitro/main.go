package main

import (
	"flag"
	"log"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

var (
	vsockPort      = flag.Uint("vsock-port", 5000, "vsock listening port")
	allowReconfig  = flag.Bool("allow-reconfig", false, "Allow the enclave config to be set multiple times (insecure, for testing only)")
	gatewayTimeout = flag.Duration("gateway-timeout", types.DefaultGatewayRequestTimeout, "HTTP client timeout for enclave->gateway requests (secrets + capabilities). Should not exceed the enclave request timeout.")
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
	dispatcherFactory := func(gatewayURL string) app.RemoteDispatcher {
		client := gateway.NewGatewayClient(gatewayURL, att, gateway.WithTimeout(*gatewayTimeout))
		verifier := signatureverifier.NewEd25519SignatureVerifier()
		return app.NewRemoteDispatcher(client, att, types.EnclaveConfig{}, appLogger, kc, comb, verifier)
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
	confApp := app.NewConfidentialWorkflowsApp(
		sdkpb.TeeType_TEE_TYPE_AWS_NITRO, appLogger, nil,
		app.WithRemoteDispatcherFactory(dispatcherFactory),
		app.WithMaxConcurrentExecutions(limit.MaxConcurrent),
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
