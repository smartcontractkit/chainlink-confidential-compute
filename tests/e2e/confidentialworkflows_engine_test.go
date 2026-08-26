package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
	"github.com/smartcontractkit/chainlink-testing-framework/seth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink/core/scripts/cre/environment/examples/contracts/permissionless_feeds_consumer"
	keystone_changeset "github.com/smartcontractkit/chainlink/deployment/keystone/changeset"
	crelib "github.com/smartcontractkit/chainlink/system-tests/lib/cre"
	crecontracts "github.com/smartcontractkit/chainlink/system-tests/lib/cre/contracts"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment/blockchains/evm"
	confidentialrelay "github.com/smartcontractkit/chainlink/system-tests/lib/cre/features/confidentialrelay"
	creworkflow "github.com/smartcontractkit/chainlink/system-tests/lib/cre/workflow"
	ttypes "github.com/smartcontractkit/chainlink/system-tests/tests/test-helpers/configuration"

	"github.com/smartcontractkit/chainlink-confidential-compute/tests"
	creJob "github.com/smartcontractkit/chainlink-confidential-compute/tests/e2e/job"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"

	"github.com/stretchr/testify/require"
)

// ---- deferredGatewayProxy ----

// deferredGatewayProxy is a reverse proxy on a fixed port that returns 502
// until SetTarget is called with the real gateway URL. This solves the
// chicken-and-egg problem: GATEWAY_URL must be fixed before the enclave starts,
// but the real URL is only known after the CRE env comes up.
type deferredGatewayProxy struct {
	mu     sync.RWMutex
	target *url.URL
	server *http.Server
	hits   atomic.Int64
}

func newDeferredGatewayProxy(t *testing.T, port int) *deferredGatewayProxy {
	t.Helper()
	p := &deferredGatewayProxy{}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			p.mu.RLock()
			defer p.mu.RUnlock()
			if p.target != nil {
				req.URL.Scheme = p.target.Scheme
				req.URL.Host = p.target.Host
				req.Host = p.target.Host
			}
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		p.mu.RLock()
		hasTarget := p.target != nil
		p.mu.RUnlock()
		if !hasTarget {
			http.Error(w, "gateway not ready", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r)
	})
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", addr)
	require.NoError(t, err, "failed to listen on port %d for gateway proxy", port)
	p.server = &http.Server{Handler: handler}
	go func() { _ = p.server.Serve(listener) }()
	return p
}

// Hits returns the number of requests the proxy has received. Used to assert a
// dead gateway was actually reached, proving round-robin failover was exercised.
func (p *deferredGatewayProxy) Hits() int64 { return p.hits.Load() }

func (p *deferredGatewayProxy) SetTarget(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.target = u
	return nil
}

func (p *deferredGatewayProxy) Close() {
	_ = p.server.Close()
}

// ---- Nitro enclave startup for engine ----

// startNitroEnclavesForEngine starts two deferred gateway proxies (a dead one
// on :9998 and the real one on :9999), puts the comma-separated pair in the
// settings the host injects, then builds and starts Nitro enclaves for the
// confidential-workflows app. The dead-first ordering forces the enclave's
// round-robin client to fail over on its first gateway call.

// CRE-5142: enable us to use the real workflow storage service in local CRE.
// engineTestStorageKeyHex is a deterministic ed25519 seed the enclave uses to
// authenticate to the fake storage service (the fake does not verify the JWT).
const engineTestStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

// SOCKS resolves enclaveHostAddr in the parent namespace.
func enclaveHostAddr() string {
	return "127.0.0.1"
}

func startNitroEnclavesForEngine(t *testing.T, logger zerolog.Logger) (
	[]types.Enclave, []string, *deferredGatewayProxy, *deferredGatewayProxy, *fakeStorageService, func(),
) {
	t.Helper()
	// Two gateway front-proxies to exercise the enclave's round-robin failover.
	// deadProxy (:9998) never gets a target, so it always returns 502; proxy
	// (:9999) is pointed at the real gateway once the CRE env is up. gatewayUrl
	// lists the dead one FIRST, so each enclave's cursor starts there: the first
	// gateway call hits the 502 and must fail over to the healthy proxy. If
	// failover regresses, that first call fails and the workflow errors out.
	deadProxy := newDeferredGatewayProxy(t, 9998)
	proxy := newDeferredGatewayProxy(t, 9999)

	// Stand up the fake CRE storage service the enclave fetches the workflow
	// binary from. Its artifact URL is set later, once the WASM server is up
	// (see initCWEngineTestServers), but the gRPC address must be known now so it
	// can go into the settings the host injects over vsock at startup.
	storageAddr, storageSvc := startFakeStorageService(t, enclaveHostAddr())
	t.Setenv("REQUIRE_BFT_QUORUM", "true")
	t.Setenv("OUTBOUND_ALLOW_LOCAL_FOR_TESTS", "true")

	// The whole runtime configuration reaches the enclave as one opaque JSON
	// payload (ENCLAVE_SETTINGS): the host forwards it verbatim and the enclave
	// app requires the storage endpoint, storage key and gateway URL.
	host := enclaveHostAddr()
	t.Setenv("ENCLAVE_SETTINGS", fmt.Sprintf(
		`{"storageKey":%q,"storageServiceUrl":%q,"storageServiceTls":false,"gatewayUrl":%q}`,
		engineTestStorageKeyHex, storageAddr, fmt.Sprintf("http://%s:9998,http://%s:9999", host, host)))
	if !tests.UseFakeEnclave() {
		// confidential-workflows EIF is larger than confidential-http (wasmtime/CGO),
		// so it needs more memory per enclave (~1148 MiB minimum).
		t.Setenv("ENCLAVE_MEMORY_MIB", "1536")
		t.Setenv("TOTAL_MEMORY_MIB", "4096")
	}
	enclaves, configURLs, enclaveCleanup := startNitroEnclaves(t, App{Name: "confidential-workflows"}, logger)
	return enclaves, configURLs, proxy, deadProxy, storageSvc, enclaveCleanup
}

// ---- testConfidentialRelayFeature ----

// testConfidentialRelayFeature wraps the real ConfidentialRelay Feature and
// injects trusted PCRs into the DON's capability config before PreEnvStartup
// runs. This allows the relay handler to validate attestations from the
// running Nitro enclaves.
type testConfidentialRelayFeature struct {
	inner    confidentialrelay.ConfidentialRelay
	pcrsJSON string
}

func (f *testConfidentialRelayFeature) Flag() crelib.CapabilityFlag {
	return f.inner.Flag()
}

func (f *testConfidentialRelayFeature) PreEnvStartup(
	ctx context.Context,
	testLogger zerolog.Logger,
	don *crelib.DonMetadata,
	topology *crelib.Topology,
	creEnv *crelib.Environment,
) (*crelib.PreEnvStartupOutput, error) {
	if don.CapabilityConfigs == nil {
		don.CapabilityConfigs = make(map[crelib.CapabilityFlag]crelib.CapabilityConfig)
	}
	cfg, ok := don.CapabilityConfigs[crelib.ConfidentialRelayCapability]
	if !ok {
		cfg = crelib.CapabilityConfig{Values: make(map[string]any)}
	}
	if cfg.Values == nil {
		cfg.Values = make(map[string]any)
	}
	cfg.Values["trustedPCRs"] = f.pcrsJSON
	don.CapabilityConfigs[crelib.ConfidentialRelayCapability] = cfg

	return f.inner.PreEnvStartup(ctx, testLogger, don, topology, creEnv)
}

func (f *testConfidentialRelayFeature) PostEnvStartup(
	ctx context.Context,
	testLogger zerolog.Logger,
	don *crelib.Don,
	dons *crelib.Dons,
	creEnv *crelib.Environment,
) error {
	return f.inner.PostEnvStartup(ctx, testLogger, don, dons, creEnv)
}

// ---- Engine test WASM binary server ----

const engineTestBinaryFilename = "workflow-test-confidential.br.b64"
const engineTestConfigFilename = "workflow-test-config.json"
const engineTestBinaryPath = "/artifacts/" + engineTestBinaryFilename
const engineTestConfigPath = "/artifacts/" + engineTestConfigFilename
const engineTestArtifactPath = "/artifact/" + engineTestBinaryFilename

// engineTestMissingSecretConfigFilename is a second workflow config that points
// handleTrigger at a secret name ("MISSING_SECRET") that is never uploaded, so
// the relay returns a user error (vault "key does not exist") and the workflow
// fails with a user-classified error rather than a system failure.
const engineTestMissingSecretConfigFilename = "workflow-test-config-missing-secret.json"
const engineTestMissingSecretConfigPath = "/artifacts/" + engineTestMissingSecretConfigFilename

// cwEngineTestServers holds the engine-test WASM binary server state.
var cwEngineTestServers struct {
	once         sync.Once
	wasmURL      string // URL using host IP (accessible from Docker and host)
	binaryHash   []byte
	artifactDir  string // directory containing the binary and config files
	artifactHits atomic.Int64
	err          error
}

// initCWEngineTestServers compiles the engine-test WASM binary, brotli-compresses
// it, base64-encodes it, writes it to a temp file, and serves it via HTTP so
// both the test host (RegisterWithContract) and the Nitro enclaves can download it.
// The returned mux is also used to serve the config file.
func initCWEngineTestServers(configJSON string) (wasmURL string, configURL string, artifactDir string, binaryHash []byte, err error) {
	cwEngineTestServers.once.Do(func() {
		srcDir, err := filepath.Abs("testdata/workflow")
		if err != nil {
			cwEngineTestServers.err = fmt.Errorf("resolving testdata path: %w", err)
			return
		}

		tmpDir, err := os.MkdirTemp("", "cw-engine-wasm-*")
		if err != nil {
			cwEngineTestServers.err = fmt.Errorf("creating temp dir: %w", err)
			return
		}
		cwEngineTestServers.artifactDir = tmpDir

		outFile := filepath.Join(tmpDir, "workflow-test.wasm")
		cmd := exec.Command("go", "build", "-o", outFile, ".")
		cmd.Dir = srcDir
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			cwEngineTestServers.err = fmt.Errorf("compiling engine-test WASM: %s: %w", string(output), err)
			return
		}

		raw, err := os.ReadFile(outFile)
		if err != nil {
			cwEngineTestServers.err = fmt.Errorf("reading compiled WASM: %w", err)
			return
		}

		var compressed bytes.Buffer
		w := brotli.NewWriter(&compressed)
		if _, err := w.Write(raw); err != nil {
			cwEngineTestServers.err = fmt.Errorf("brotli compressing: %w", err)
			return
		}
		if err := w.Close(); err != nil {
			cwEngineTestServers.err = fmt.Errorf("brotli close: %w", err)
			return
		}

		binary := compressed.Bytes()
		hash := sha256.Sum256(binary)
		cwEngineTestServers.binaryHash = hash[:]

		encoded := base64.StdEncoding.EncodeToString(binary)

		// Write encoded binary to file so it can be copied to Docker containers.
		artifactFile := filepath.Join(tmpDir, engineTestBinaryFilename)
		if err := os.WriteFile(artifactFile, []byte(encoded), 0o644); err != nil {
			cwEngineTestServers.err = fmt.Errorf("writing artifact file: %w", err)
			return
		}

		// Write config file alongside the binary so it can be copied to containers too.
		configFile := filepath.Join(tmpDir, engineTestConfigFilename)
		if err := os.WriteFile(configFile, []byte(configJSON), 0o644); err != nil {
			cwEngineTestServers.err = fmt.Errorf("writing config file: %w", err)
			return
		}

		// Serve both binary and config on HTTP with filename paths so
		// RegisterWithContract can download them and constructArtifactURL can
		// derive container filenames.
		mux := http.NewServeMux()
		mux.HandleFunc(engineTestBinaryPath, func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(encoded))
		})
		mux.HandleFunc(engineTestArtifactPath, func(rw http.ResponseWriter, r *http.Request) {
			cwEngineTestServers.artifactHits.Add(1)
			_, _ = rw.Write([]byte(encoded))
		})
		mux.HandleFunc(engineTestConfigPath, func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(configJSON))
		})
		// Serve a second config that requests a secret never uploaded to the vault,
		// exercising the missing-secret → user-error classification path. Echo and
		// chain-write are disabled (empty fields) so the workflow fails at GetSecret
		// before reaching the later legs.
		mux.HandleFunc(engineTestMissingSecretConfigPath, func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(`{"secret_id":"MISSING_SECRET"}`))
		})
		wasmListener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			cwEngineTestServers.err = fmt.Errorf("wasm listener: %w", err)
			return
		}
		wasmSrv := &http.Server{Handler: mux}
		go func() { _ = wasmSrv.Serve(wasmListener) }()

		hostIP := getHostIP()
		port := wasmListener.Addr().(*net.TCPAddr).Port
		cwEngineTestServers.wasmURL = fmt.Sprintf("http://%s:%d%s", hostIP, port, engineTestBinaryPath)
	})

	baseURL := cwEngineTestServers.wasmURL
	if baseURL != "" {
		// Derive configURL from the same host:port as wasmURL, just with a different filename.
		configURL = baseURL[:len(baseURL)-len(engineTestBinaryFilename)] + engineTestConfigFilename
	}

	return cwEngineTestServers.wasmURL, configURL, cwEngineTestServers.artifactDir, cwEngineTestServers.binaryHash, cwEngineTestServers.err
}

// ---- Engine test ----

// testConfidentialWorkflowsEngine validates the engine path:
// syncer -> ConfidentialModule -> confidential-workflows capability -> enclave ->
// WASM (Subscribe + Trigger) -> GetSecret (remote dispatch to VaultDON) +
// http.SendRequest with ConsensusMedianAggregation (intercepted locally by the
// enclave: http-actions + consensus/Simple both handled in-process) +
// ReportFromDon/evm.WriteReport (routed back OUT of the enclave to the DONs, since
// report signing and chain writes are consensus-bound).
//
// Success signals:
//   - "engine-test-secret" + the expected secret value in workflow-DON logs.
//   - "engine-test-http" + status=200 in workflow-DON logs.
//   - the reported price readable via getPrice on the deployed consumer contract.
//
// Echo target: https://postman-echo.com/post. The EIF-baked DefaultPolicy
// (https over 443, safeurl privateNetworks blocking) passes public TLS.
// fakeStorageService is a minimal in-process CRE storage NodeService for the
// engine E2E. The enclave now fetches the workflow binary itself: it calls
// DownloadArtifact over JWT-authed gRPC, gets a pre-signed URL, downloads it,
// and verifies binary_hash. This fake returns the URL of the (base64) WASM
// server that initCWEngineTestServers already stands up. The URL is set once
// that server is up (setURL), which is before any workflow executes.
type fakeStorageService struct {
	storage_service.UnimplementedNodeServiceServer
	mu     sync.Mutex
	url    string
	lastID string
}

func (f *fakeStorageService) setURL(u string) {
	f.mu.Lock()
	f.url = u
	f.mu.Unlock()
}

func (f *fakeStorageService) lastArtifactID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastID
}

func (f *fakeStorageService) DownloadArtifact(_ context.Context, req *storage_service.DownloadArtifactRequest) (*storage_service.DownloadArtifactResponse, error) {
	f.mu.Lock()
	f.lastID = req.GetId()
	u := f.url
	f.mu.Unlock()

	// Mirror real storage-service semantics: the id must be a bare artifact id,
	// not a full URL. The enclave once sent the whole BinaryUrl here and real
	// storage returned NotFound; reject the same shape so that regression fails
	// this e2e instead of only surfacing in a live environment.
	if strings.Contains(req.GetId(), "://") {
		return nil, status.Errorf(codes.NotFound, "fake storage: artifact with id %q not found (expected a bare id, not a URL)", req.GetId())
	}
	if u == "" {
		return nil, fmt.Errorf("fake storage: artifact url not set yet")
	}
	return &storage_service.DownloadArtifactResponse{Url: u}, nil
}

func startFakeStorageService(t *testing.T, enclaveHost string) (string, *fakeStorageService) {
	t.Helper()
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err, "fake storage listener")

	svc := &fakeStorageService{}
	grpcSrv := grpc.NewServer()
	storage_service.RegisterNodeServiceServer(grpcSrv, svc)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	port := lis.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("%s:%d", enclaveHost, port), svc
}

func testConfidentialWorkflowsEngine(t *testing.T, testLogger zerolog.Logger, buildLocalBinaries func() error) {
	t.Helper()
	if os.Getenv("REMOTE_ENCLAVE_URLS") != "" || tests.UseLegacyEnclaves() {
		t.Skip("engine test does not run against remote/legacy enclaves")
	}
	if os.Getenv("PRIOR_VERSION_BINARY_PATHS") != "" {
		t.Skip("engine test does not run against prior-version capability binaries")
	}
	// Engine test needs the multi-DON topology (workflow + capabilities) with the
	// confidential-workflows capability registered. The http subtest runs first
	// with workflow-don.toml; override for our scope only.
	t.Setenv("CTF_CONFIGS", "configs/workflow-don-engine.toml")
	// Register docker log dumping FIRST so it runs LAST (cleanups run in reverse
	// order). Captures workflow-node container logs on failure, which is the
	// only way to diagnose engine execution errors (GetSecret / http-actions /
	// consensus interceptions) once the job completes and containers are torn
	// down.
	t.Cleanup(func() { dumpDockerLogs(t, testLogger, 500) })
	creJob.ResetDeliveryState()

	// 1. Pick the echo target. Nitro uses postman-echo; the EIF's baked-in
	//    DefaultPolicy allows it.
	echoURL := "https://postman-echo.com/post"

	// 2. Start Nitro enclaves for the confidential-workflows app. This also
	//    stands up the fake CRE storage service and puts its endpoint and the
	//    storage key in ENCLAVE_SETTINGS; storageSvc's artifact URL is populated
	//    once the WASM server is up (below).
	enclaves, configURLs, gwProxy, deadGwProxy, storageSvc, enclaveCleanup := startNitroEnclavesForEngine(t, testLogger)
	defer enclaveCleanup()
	defer gwProxy.Close()
	defer deadGwProxy.Close()

	// 2. Create capability job for confidential-workflows.
	confCap, err := creJob.New("confidential-workflows", "1.0.0-alpha", "confidential-workflows", enclaves)
	require.NoError(t, err, "failed to create confidential-workflows capability job")

	// Register all app capability stubs so config validation passes.
	allCaps := []crelib.InstallableCapability{confCap}
	for _, app := range apps {
		if app.Name != "confidential-workflows" {
			stub, cErr := creJob.New(app.Name, app.Version, app.Name, nil)
			require.NoError(t, cErr, "failed to create capability stub for %s", app.Name)
			allCaps = append(allCaps, stub)
		}
	}

	// 3. Set up CRE environment with ConfidentialRelay feature and MOCK_SECRET.
	// Use real PCR measurements from built EIF. Relay attestation validation
	// falls back to the default AWS Nitro root CA.
	// Reusable EIFs share PCR values across CIDs.
	var pcrsJSON string
	if tests.UseFakeEnclave() {
		// Fake enclaves emit a sentinel attestation document instead of real
		// PCRs, so pass the fake measurement placeholder. The relay handler's
		// fake-aware validation path matches against this rather than parsing a
		// Nitro attestation. (Marshaling the raw "fake-measurements" bytes as
		// json.RawMessage would fail since it isn't valid JSON.)
		b, mErr := json.Marshal([]string{types.FakeMeasurements})
		require.NoError(t, mErr, "failed to marshal fake measurements")
		pcrsJSON = string(b)
	} else {
		var allPCRs []json.RawMessage
		for _, enc := range enclaves {
			for _, tv := range enc.TrustedValues {
				if string(tv) != "invalid" {
					allPCRs = append(allPCRs, json.RawMessage(tv))
				}
			}
		}
		pcrsBytes, mErr := json.Marshal(allPCRs)
		require.NoError(t, mErr, "failed to marshal PCR measurements")
		pcrsJSON = string(pcrsBytes)
	}
	relayFeature := crelib.Feature(&testConfidentialRelayFeature{
		// Mode-aware: trust enclaves (skip TEE attestation validation) only when
		// running against fake enclaves. Real (nightly) runs keep full validation.
		inner:    confidentialrelay.ConfidentialRelay{TrustEnclaves: tests.UseFakeEnclave()},
		pcrsJSON: pcrsJSON,
	})

	names := []string{"MOCK_SECRET"}
	secretValues := []string{"s3cret-from-vault"}
	testEnv := mustInitializeCapabilitySetup(
		t,
		engineDONConfigFile,
		configURLs,
		allCaps,
		buildLocalBinaries,
		nil, // extraAllowedPorts
		testLogger,
		names,
		secretValues,
		workflowOwner,
		relayFeature,
	)

	// 4. Initialize dispatcher/proxy with the gateway URL.
	gwIncoming := testEnv.Dons.GatewayConnectors.Configurations[0].Incoming
	gwHost := gwIncoming.Host
	if gwHost == "" {
		gwHost = getHostIP()
	}
	gatewayURL := fmt.Sprintf("%s://%s:%d%s", gwIncoming.Protocol, gwHost, gwIncoming.ExternalPort, gwIncoming.Path)
	require.NoError(t, gwProxy.SetTarget(gatewayURL), "failed to set gateway proxy target")
	testLogger.Info().Msgf("Gateway proxy target set to: %s", gatewayURL)

	// 4b. Inject the vault public key into the vault@1.0.0 capability config.
	// The workflow engine's pre-enclave secret fetch reads VaultPublicKey + Threshold
	// from that capability's on-chain registry config
	// (chainlink core/services/workflows/v2/secrets.go). The capability is registered
	// with an empty config, so rt.GetSecret() fails with "cannot unwrap nil
	// values.Map" until we inject the key. The vault DON produces the key via DKG;
	// fetch it through the gateway and write it into the registry config, mirroring
	// the system-tests CRE flow.
	vaultCtx := t.Context()
	vaultPublicKey, vpkErr := creworkflow.FetchVaultPublicKey(vaultCtx, gatewayURL)
	require.NoError(t, vpkErr, "failed to fetch vault public key from gateway")
	testLogger.Info().Msgf("Fetched vault public key: %s", vaultPublicKey)

	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain")
	vaultSethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient
	capRegAddr := crecontracts.MustGetAddressFromDataStore(
		testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(), //nolint:staticcheck // mirrors system-tests usage
		keystone_changeset.CapabilitiesRegistry.String(),
		testEnv.CreEnvironment.ContractVersions[keystone_changeset.CapabilitiesRegistry.String()],
		"",
	)
	vaultDON, _, vdErr := crelib.GetVaultCapabilityDON(vaultCtx, vaultSethClient, capRegAddr)
	require.NoError(t, vdErr, "failed to locate vault capability DON in registry")
	// Threshold 1 matches the 4-node F=1 vault DON (see setEnclaveConfig in e2e_test.go).
	require.NoError(t,
		creworkflow.UpdateVaultCapabilityConfig(vaultCtx, vaultSethClient, capRegAddr, vaultDON, vaultPublicKey, 1),
		"failed to inject VaultPublicKey/Threshold into vault@1.0.0 capability config")
	testLogger.Info().Msg("Injected VaultPublicKey + Threshold into vault@1.0.0 capability config")

	// 4c. Deploy the report receiver the workflow writes to. PermissionlessFeedsConsumer
	// has no access control on onReport and exposes getPrice, so the test can assert
	// the write landed on-chain rather than trusting a log line.
	consumerAddr := deployFeedsConsumer(t, sethClientFor(t, testEnv), testLogger)
	chainSelector := testEnv.CreEnvironment.Blockchains[0].ChainSelector() //nolint:staticcheck // mirrors system-tests usage

	// 5. Compile engine-test WASM, serve binary + config, and copy to Docker containers.
	configJSON := fmt.Sprintf(
		`{"echo_url":%q,"consumer_address":%q,"chain_selector":%d,"feed_id":%q,"price":%d}`,
		echoURL, consumerAddr.Hex(), chainSelector, engineTestFeedID, engineTestPrice,
	)
	wasmURL, configURL, artifactDir, _, initErr := initCWEngineTestServers(configJSON)
	require.NoError(t, initErr, "failed to initialize engine-test WASM server")
	testLogger.Info().Msgf("Engine-test WASM binary served at %s", wasmURL)
	testLogger.Info().Msgf("Engine-test config served at %s", configURL)

	// Point the fake storage service at the (base64) WASM the enclave will fetch.
	wasmParsed, perr := url.Parse(wasmURL)
	require.NoError(t, perr, "parsing engine-test WASM URL")
	storageSvc.setURL(fmt.Sprintf("http://%s:%s%s", enclaveHostAddr(), wasmParsed.Port(), engineTestArtifactPath))

	// Copy the binary and config to workflow DON containers so the syncer's
	// file-based fetcher can read them.
	for _, don := range testEnv.Dons.List() {
		if !don.HasFlag(crelib.WorkflowDON) {
			continue
		}
		// Copy WASM binary.
		copyErr := creworkflow.CopyArtifactsToDockerContainers(
			creworkflow.DefaultWorkflowTargetDir,
			ns.NodeNamePrefix(don.Name),
			filepath.Join(artifactDir, engineTestBinaryFilename),
		)
		require.NoError(t, copyErr, "failed to copy engine-test binary to Docker containers")
		// Copy config file.
		copyErr = creworkflow.CopyArtifactsToDockerContainers(
			creworkflow.DefaultWorkflowTargetDir,
			ns.NodeNamePrefix(don.Name),
			filepath.Join(artifactDir, engineTestConfigFilename),
		)
		require.NoError(t, copyErr, "failed to copy engine-test config to Docker containers")
	}

	// 5b. Capture enclave memory usage before the workflow is deployed and running.
	//     Baseline reflects idle, configured enclaves that have not yet loaded or
	//     executed any WASM. The enclaves require the x-api-key header (matching
	//     job.go's "foobar"); attach it so direct /memory reads aren't rejected with
	//     401 (enclave 0 sits behind the auth-enforcing proxy).
	authedEnclaves := make([]types.Enclave, len(enclaves))
	copy(authedEnclaves, enclaves)
	for i := range authedEnclaves {
		authedEnclaves[i].EnclaveAuthHeader = "x-api-key: foobar"
	}
	memBefore := totalEnclaveMemoryMB(t, authedEnclaves, testLogger)
	testLogger.Info().Uint64("totalUsedMB", memBefore).Msg("Total enclave memory before workflow deploy")

	// 6. Deploy the confidential workflow with attributes and configURL.
	workflowID := deployConfidentialWorkflowForEngine(t, testEnv, testLogger, wasmURL, configURL)

	// 7. Wait for the workflow engine's "Workflow execution finished successfully"
	//    log line with our workflowID. The engine emits that line (engine.go:886)
	//    at INFO level ONLY per successful trigger execution - not for the
	//    Subscribe-phase enclave call that runs once at engine startup. Given
	//    our WASM returns (nil, err) if either rt.GetSecret or http.SendRequest
	//    fails, this log + our workflowID implies:
	//      - cron trigger fired
	//      - workflow-DON reached the enclave successfully
	//      - GetSecret → VaultDON remote dispatch succeeded
	//      - http-actions was intercepted in-enclave and the HTTPS fetch succeeded
	//      - consensus/Simple was intercepted and returned the single observation
	//    WASM runtime.Logger() lines do NOT surface: enclaveExecutionHelper.EmitUserLog
	//    is a no-op stub today, with PRIV-443 tracking the wiring. So we rely on this
	//    engine-level log.
	waitForWorkflowExecutionComplete(t, testEnv, testLogger, workflowID, 5*time.Minute)

	require.Equal(t, engineTestBinaryFilename, storageSvc.lastArtifactID(), "unexpected artifact requested from storage")
	require.Positive(t, cwEngineTestServers.artifactHits.Load(), "enclave never downloaded the artifact URL returned by storage")

	// The GetSecret path routes through the enclave's gateway client, configured
	// with a dead gateway first (:9998) and the real one second (:9999). The
	// workflow only finishes if every gateway call failed over from the dead
	// proxy to the healthy one. Assert the dead proxy was actually hit, so this
	// test genuinely exercises round-robin failover rather than passing vacuously
	// (e.g. if the cursor logic changed to skip the first URL).
	require.Positive(t, deadGwProxy.Hits(), "dead gateway proxy was never hit; round-robin failover was not exercised")
	require.Positive(t, gwProxy.Hits(), "healthy gateway proxy was never reached after failover")

	// 7b. The engine log above only proves the WASM returned without error. Read the
	// consumer contract back to prove the report was actually signed by the DON
	// (consensus.Report via ReportFromDon) and delivered on-chain by the forwarder
	// (evm.WriteReport via UsingTheDons) — the two legs a TEE handler has to route
	// out of the enclave. A stale/zero value here means the write leg silently
	// no-op'd even though the workflow reported success.
	assertFeedReportWritten(t, sethClientFor(t, testEnv), consumerAddr, testLogger, 2*time.Minute)

	// 8. The workflow has now loaded and executed inside the enclaves (WASM runtime
	//    + binary resident, requests processed). The reported memory usage should
	//    differ from the pre-deploy baseline, exercising the /memory endpoint end
	//    to end (enclave server -> host proxy).
	memAfter := totalEnclaveMemoryMB(t, authedEnclaves, testLogger)
	testLogger.Info().Uint64("totalUsedMB", memAfter).Uint64("baselineMB", memBefore).Msg("Total enclave memory after workflow execution")
	require.Greater(t, memAfter, memBefore, "enclave memory usage should grow after running the workflow (WASM runtime + binary loaded)")
	// Upper bound as a regression tripwire: the executing enclave typically settles
	// around ~67MB (idle ~18MB + WASM runtime/binary/execution), for a total near
	// 85MB across both enclaves. Flag if we start consuming substantially more.
	require.Less(t, memAfter, uint64(100), "total enclave memory should stay under 100MB; a large jump may indicate a leak or regression")

	// 9. Missing-secret → user-error classification. Deploy a workflow whose
	//    config requests a secret ("MISSING_SECRET") that was never uploaded to
	//    the vault. The relay DON maps the vault's "key does not exist" to a
	//    JSON-RPC ErrInvalidParams (a user error) once the relay-node fix ships;
	//    the enclave surfaces the cause in the engine's "Workflow execution
	//    failed" log. This sub-case reuses the already-running CRE env and the
	//    same WASM binary (the secret name is config-driven via the SecretID
	//    field).
	//
	//    The happy-path workflow is torn down first: running two concurrent
	//    confidential workflows in one enclave starves the second workflow's
	//    gateway/relay dispatch (its GetSecrets calls hit outbound-proxy
	//    resets and never reach the relay), so its executions never produce an
	//    engine failure log. Deleting the first workflow and briefly letting
	//    the engine wind it down leaves the enclave servicing a single workflow.
	//
	//    NOTE: this asserts the post-fix behavior (error message contains
	//    "key does not exist"). Against a chainlink version predating the
	//    relay-node user-error fix, the message is "relay quorum unreachable"
	//    with an "internal error" code, so this assertion is the gate that
	//    confirms the fix is live. Bump tests/go.mod to the chainlink commit
	//    carrying the fix before expecting this to pass.
	deleteConfidentialWorkflowForEngine(t, testEnv, testLogger, "engine-test-confidential")
	// Give the engine a beat to stop triggering the deleted workflow before the
	// next one starts, so the two never overlap on the enclave's gateway path.
	time.Sleep(15 * time.Second)
	missingSecretConfigURL := configURL[:len(configURL)-len(engineTestConfigFilename)] + engineTestMissingSecretConfigFilename
	missingSecretWorkflowID := deployConfidentialWorkflowForEngineWithID(t, testEnv, testLogger, wasmURL, missingSecretConfigURL, "engine-test-missing-secret")
	failureLine := waitForWorkflowExecutionFailure(t, testEnv, testLogger, missingSecretWorkflowID, "key does not exist", 5*time.Minute)
	// The relay fix surfaces the actual vault cause and carries the
	// ErrInvalidParams code (-32602): a user error. Assert both the positive
	// (invalid-params code + vault cause present) and the negative (the generic
	// "internal error" masking, errorCode -32603, must not appear).
	require.Contains(t, string(failureLine), "JSON-RPC error -32602", "missing-secret failure must carry the ErrInvalidParams code, not an internal error")
	require.NotContains(t, string(failureLine), "internal error", "missing-secret failure must be classified as a user error, not an internal error")

	testLogger.Info().Msg("Engine-path E2E test passed: VaultDON remote dispatch + in-enclave http-actions interception + DON-signed chain write validated")
}

// engineTestFeedID / engineTestPrice are the feed the confidential workflow reports
// on-chain. The price is an arbitrary fixed sentinel so the read-back is an exact
// equality check rather than a "changed from zero" heuristic.
const (
	engineTestFeedID = "0x018bfe8840000000000000000000000000000000000000000000000000000000"
	engineTestPrice  = uint64(4242424242)
)

// sethClientFor returns the funded seth client for the test's EVM chain.
func sethClientFor(t *testing.T, testEnv *ttypes.TestEnvironment) *seth.Client {
	t.Helper()
	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain")
	return testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient
}

// deployFeedsConsumer deploys PermissionlessFeedsConsumer, the report receiver the
// confidential workflow writes to. Its onReport is unauthenticated, so no forwarder
// allowlisting is needed for the DON's write to land.
func deployFeedsConsumer(t *testing.T, sethClient *seth.Client, testLogger zerolog.Logger) common.Address {
	t.Helper()

	consABI, abiErr := permissionless_feeds_consumer.PermissionlessFeedsConsumerMetaData.GetAbi()
	require.NoError(t, abiErr, "failed to get PermissionlessFeedsConsumer ABI")

	data, deployErr := sethClient.DeployContract(
		sethClient.NewTXOpts(),
		"PermissionlessFeedsConsumer",
		*consABI,
		common.FromHex(permissionless_feeds_consumer.PermissionlessFeedsConsumerMetaData.Bin),
	)
	require.NoError(t, deployErr, "failed to deploy PermissionlessFeedsConsumer")
	testLogger.Info().Msgf("Deployed PermissionlessFeedsConsumer at %s", data.Address.Hex())
	return data.Address
}

// assertFeedReportWritten polls getPrice(feedID) until the workflow's report shows up
// with the exact price the WASM was configured to write, then checks the stored
// timestamp is sane. The workflow's cron fires every 30s and the forwarder needs a
// block or two, so this polls rather than reading once.
func assertFeedReportWritten(
	t *testing.T,
	sethClient *seth.Client,
	consumerAddr common.Address,
	testLogger zerolog.Logger,
	timeout time.Duration,
) {
	t.Helper()

	consumer, err := permissionless_feeds_consumer.NewPermissionlessFeedsConsumer(consumerAddr, sethClient.Client)
	require.NoError(t, err, "failed to bind PermissionlessFeedsConsumer at %s", consumerAddr.Hex())

	feedID, err := parseEngineTestFeedID()
	require.NoError(t, err, "failed to parse engine test feed id")

	want := new(big.Int).SetUint64(engineTestPrice)
	deadline := time.Now().Add(timeout)
	var lastPrice *big.Int
	var lastTimestamp uint32
	for {
		price, timestamp, callErr := consumer.GetPrice(&bind.CallOpts{Context: t.Context()}, feedID)
		if callErr == nil {
			lastPrice, lastTimestamp = price, timestamp
			if price != nil && price.Cmp(want) == 0 {
				testLogger.Info().
					Str("price", price.String()).
					Uint32("timestamp", timestamp).
					Str("consumer", consumerAddr.Hex()).
					Msg("Chain write verified on-chain: DON-signed report from TEE handler landed in the consumer")
				require.Positive(t, timestamp, "stored feed timestamp should be non-zero")
				return
			}
		} else {
			testLogger.Info().Msgf("getPrice call failed, retrying: %v", callErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for feed report at %s: got price=%v timestamp=%d, want price=%s",
				timeout, consumerAddr.Hex(), lastPrice, lastTimestamp, want)
		}
		time.Sleep(5 * time.Second)
	}
}

func parseEngineTestFeedID() ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(engineTestFeedID, "0x"))
	if err != nil {
		return id, err
	}
	if len(b) != 32 {
		return id, fmt.Errorf("feed id decoded to %d bytes, want 32", len(b))
	}
	copy(id[:], b)
	return id, nil
}

// enclaveUsedMemoryMB queries an enclave's /memory endpoint and returns the
// megabytes of memory it reports in use.
func enclaveUsedMemoryMB(enclave types.Enclave) (uint64, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, enclave.EnclaveURL+types.MemoryPath, nil)
	if err != nil {
		return 0, err
	}
	if err := util.SetAuthHeader(enclave, req); err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer util.SafeClose(resp)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("memory endpoint returned status %d", resp.StatusCode)
	}
	var out types.MemoryEstimateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.UsedMB, nil
}

// totalEnclaveMemoryMB sums the in-use memory reported across all enclaves. It
// requires every enclave to be reachable so before/after measurements cover the
// same set.
func totalEnclaveMemoryMB(t *testing.T, enclaves []types.Enclave, testLogger zerolog.Logger) uint64 {
	t.Helper()
	var total uint64
	for _, enc := range enclaves {
		mb, err := enclaveUsedMemoryMB(enc)
		require.NoError(t, err, "failed to query /memory for enclave %s", enc.EnclaveURL)
		testLogger.Info().Str("enclave", enc.EnclaveURL).Uint64("usedMB", mb).Msg("enclave memory usage")
		total += mb
	}
	return total
}

// waitForWorkflowExecutionComplete polls `docker logs` on every workflow-DON
// chainlink container until a line contains both `"msg":"Workflow execution
// finished successfully"` and the given workflowID on the same line. The
// workflow engine emits that line (from engine.go:886) at INFO level ONLY per
// successful trigger execution - not for the Subscribe-phase enclave call that
// runs once at engine startup. Matching it therefore proves the cron trigger
// fired, the WASM ran to completion, and every capability call (GetSecret,
// http.SendRequest) in handleTrigger succeeded.
func waitForWorkflowExecutionComplete(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	testLogger zerolog.Logger,
	workflowID string,
	timeout time.Duration,
) {
	t.Helper()

	containers := workflowDONContainerNames(testEnv)
	require.NotEmpty(t, containers, "no workflow-DON containers found to scrape")
	needleMsg := []byte(`"msg":"Workflow execution finished successfully"`)
	needleID := []byte(workflowID)
	testLogger.Info().Msgf("Waiting for successful-trigger log for workflowID %s on %d container(s): %v", workflowID, len(containers), containers)

	deadline := time.Now().Add(timeout)
	for {
		for _, name := range containers {
			out, _ := exec.Command("docker", "logs", "--tail", "10000", name).CombinedOutput()
			for _, line := range bytes.Split(out, []byte{'\n'}) {
				if bytes.Contains(line, needleMsg) && bytes.Contains(line, needleID) {
					testLogger.Info().Msgf("Found successful-trigger log in container %s for workflowID %s", name, workflowID)
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for successful-trigger log with workflowID %s", timeout, workflowID)
		}
		testLogger.Info().Msg("Successful-trigger log not found yet, retrying in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// waitForWorkflowExecutionFailure polls `docker logs` on every workflow-DON
// container until a line contains the "Workflow execution failed" message, the
// given workflowID, and the needle substring (e.g. the user-error marker
// "key does not exist"). Matching it proves the workflow ran, hit the expected
// failure, and that the failure message reached the engine logs with the
// expected classification. Returns the matching log line.
func waitForWorkflowExecutionFailure(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	testLogger zerolog.Logger,
	workflowID string,
	needleMsg string,
	timeout time.Duration,
) []byte {
	t.Helper()

	containers := workflowDONContainerNames(testEnv)
	require.NotEmpty(t, containers, "no workflow-DON containers found to scrape")
	needleFailed := []byte(`"msg":"Workflow execution failed"`)
	needleID := []byte(workflowID)
	needle := []byte(needleMsg)
	testLogger.Info().Msgf("Waiting for failure log for workflowID %s with needle %q on %d container(s)", workflowID, needleMsg, len(containers))

	deadline := time.Now().Add(timeout)
	for {
		for _, name := range containers {
			out, _ := exec.Command("docker", "logs", "--tail", "10000", name).CombinedOutput()
			for _, line := range bytes.Split(out, []byte{'\n'}) {
				if bytes.Contains(line, needleFailed) && bytes.Contains(line, needleID) && bytes.Contains(line, needle) {
					testLogger.Info().Msgf("Found failure log in container %s for workflowID %s", name, workflowID)
					return line
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for failure log with workflowID %s and needle %q", timeout, workflowID, needleMsg)
		}
		testLogger.Info().Msg("Failure log not found yet, retrying in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// workflowDONContainerNames returns the chainlink container names for every
// nodeset whose DON hosts the workflow DON flag.
func workflowDONContainerNames(testEnv *ttypes.TestEnvironment) []string {
	workflowDONNames := map[string]bool{}
	for _, don := range testEnv.Dons.List() {
		if don.HasFlag(crelib.WorkflowDON) {
			workflowDONNames[don.Name] = true
		}
	}

	var names []string
	for _, ns := range testEnv.Config.NodeSets {
		if !workflowDONNames[ns.Name] {
			continue
		}
		if ns.Out == nil {
			continue
		}
		for _, cl := range ns.Out.CLNodes {
			if cl == nil || cl.Node == nil || cl.Node.ContainerName == "" {
				continue
			}
			names = append(names, cl.Node.ContainerName)
		}
	}
	return names
}

// deployConfidentialWorkflowForEngine registers a confidential workflow with the
// on-chain registry and returns the on-chain workflow ID. The binaryURL points
// to the engine-test WASM binary HTTP server. The attributes mark the workflow
// as confidential with MOCK_SECRET.
func deployConfidentialWorkflowForEngine(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	testLogger zerolog.Logger,
	binaryURL string,
	configURL string,
) string {
	t.Helper()
	return deployConfidentialWorkflowForEngineWithID(t, testEnv, testLogger, binaryURL, configURL, "engine-test-confidential")
}

// deployConfidentialWorkflowForEngineWithID is the name-taking variant, used to
// deploy a second workflow alongside the happy-path one without colliding on
// the on-chain workflow name (e.g. the missing-secret sub-case).
func deployConfidentialWorkflowForEngineWithID(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	testLogger zerolog.Logger,
	binaryURL string,
	configURL string,
	workflowName string,
) string {
	t.Helper()

	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0])
	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient

	wfRegistryRef := crecontracts.MustGetAddressRefFromDataStore(
		testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(),
		keystone_changeset.WorkflowRegistry.String(),
		testEnv.CreEnvironment.ContractVersions[keystone_changeset.WorkflowRegistry.String()],
		"",
	)

	attributes := []byte(`{"confidential":true}`)

	testLogger.Info().Msgf("Registering confidential workflow %q (binaryURL=%s, configURL=%s, attributes=%s)", workflowName, binaryURL, configURL, string(attributes))

	configURLPtr := &configURL
	workflowID, err := creworkflow.RegisterWithContract(
		context.Background(),
		sethClient,
		common.HexToAddress(wfRegistryRef.Address),
		wfRegistryRef.Version,
		0, // donID unused for v2
		testEnv.Dons.MustWorkflowDON().DonFamily,
		workflowName,
		"some-tag", // workflowTag
		binaryURL,
		configURLPtr,
		nil, // no secrets URL
		attributes,
		nil, // keep HTTP URL on-chain; enclave fetches binary via HTTP, syncer file-fetcher extracts filename from URL path
	)
	require.NoError(t, err, "failed to register confidential workflow")
	testLogger.Info().Msgf("Confidential workflow %q registered: %s", workflowName, workflowID)

	t.Cleanup(func() {
		testLogger.Info().Msgf("Cleaning up confidential workflow %q...", workflowName)
		_ = creworkflow.DeleteWithContract(
			context.Background(),
			sethClient,
			common.HexToAddress(wfRegistryRef.Address),
			wfRegistryRef.Version,
			workflowName,
		)
	})

	return workflowID
}

// deleteConfidentialWorkflowForEngine removes a workflow from the on-chain
// registry so the engine stops triggering it. Used to tear down the happy-path
// workflow before the missing-secret sub-case deploys its own, so the enclave
// only services one workflow at a time.
func deleteConfidentialWorkflowForEngine(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	testLogger zerolog.Logger,
	workflowName string,
) {
	t.Helper()

	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0])
	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient

	wfRegistryRef := crecontracts.MustGetAddressRefFromDataStore(
		testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(),
		keystone_changeset.WorkflowRegistry.String(),
		testEnv.CreEnvironment.ContractVersions[keystone_changeset.WorkflowRegistry.String()],
		"",
	)

	testLogger.Info().Msgf("Deleting confidential workflow %q...", workflowName)
	require.NoError(t, creworkflow.DeleteWithContract(
		context.Background(),
		sethClient,
		common.HexToAddress(wfRegistryRef.Address),
		wfRegistryRef.Version,
		workflowName,
	), "failed to delete confidential workflow")
}
