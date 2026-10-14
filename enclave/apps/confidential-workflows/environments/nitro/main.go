package main

import (
	"flag"
	"log"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/nitrotransport"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/memlimit"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/wasmruntime"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
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

	// The host owns storage downloads and forwards the full runtime settings
	// over vsock. This factory validates gateway configuration when settings
	// arrive; execution workers construct their own dispatchers.
	dispatcherFactory := func(gw app.GatewayConfig) (app.RemoteDispatcher, error) {
		return nitrotransport.Dispatcher(gw, types.EnclaveConfig{}, att, kc, appLogger, 0)
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
	// Nitro mounts /tmp noexec; serialized modules need executable mappings.
	compiler, err := wasmruntime.NewCompiler("/var/lib/workflow-artifacts")
	if err != nil {
		logger.Fatalf("Failed to construct workflow compiler: %v", err)
	}
	defer func() {
		if err := compiler.Close(); err != nil {
			appLogger.Warnw("closing workflow compiler", "error", err)
		}
	}()
	confApp, err := app.NewConfidentialWorkflowsApp(
		sdkpb.TeeType_TEE_TYPE_AWS_NITRO,
		appLogger,
		app.Config{
			Compiler:                compiler,
			Worker:                  processes,
			GatewayTimeout:          *gatewayTimeout,
			RemoteDispatcherFactory: dispatcherFactory,
			HTTPFetcher:             nitrotransport.HTTPFetcher(0),
			MaxConcurrentExecutions: limit.MaxConcurrent,
		},
	)
	if err != nil {
		logger.Fatalf("Failed to construct confidential workflows app: %v", err)
	}

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
