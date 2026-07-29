package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	storage_service "github.com/smartcontractkit/chainlink-protos/storage-service/go"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
// chicken-and-egg problem: the enclave's EIF must bake in the gateway URL at
// build time, but the real URL is only known after the CRE env starts.
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
// on :9998 and the real one on :9999), sets GATEWAY_URL to the comma-separated
// pair so the EIF bakes it in, then builds and starts Nitro enclaves for the
// confidential-workflows app. The dead-first ordering forces the enclave's
// round-robin client to fail over on its first gateway call.

// CRE-5142: enable us to use the real workflow storage service in local CRE.
// engineTestStorageKeyHex is a deterministic ed25519 seed the enclave uses to
// authenticate to the fake storage service (the fake does not verify the JWT).
const engineTestStorageKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

// enclaveHostAddr is the address the enclave reaches host-local test servers at:
// loopback for fake enclaves (local processes), the wg0 host IP for real Nitro.
func enclaveHostAddr() string {
	if tests.UseFakeEnclave() {
		return "localhost"
	}
	return "100.64.0.3"
}

func startNitroEnclavesForEngine(t *testing.T, logger zerolog.Logger) (
	[]types.Enclave, []string, *deferredGatewayProxy, *deferredGatewayProxy, *fakeStorageService, func(),
) {
	t.Helper()
	// Two gateway front-proxies to exercise the enclave's round-robin failover.
	// deadProxy (:9998) never gets a target, so it always returns 502; proxy
	// (:9999) is pointed at the real gateway once the CRE env is up. GATEWAY_URL
	// lists the dead one FIRST, so each enclave's cursor starts there: the first
	// gateway call hits the 502 and must fail over to the healthy proxy. If
	// failover regresses, that first call fails and the workflow errors out.
	deadProxy := newDeferredGatewayProxy(t, 9998)
	proxy := newDeferredGatewayProxy(t, 9999)

	// Stand up the fake CRE storage service the enclave fetches the workflow
	// binary from. Its artifact URL is set later, once the WASM server is up
	// (see initCWEngineTestServers), but the gRPC address must be known now so
	// STORAGE_SERVICE_URL can be baked into the EIF. STORAGE_KEY is injected by
	// the host into the enclave over vsock at startup.
	storageAddr, storageSvc := startFakeStorageService(t, enclaveHostAddr())
	t.Setenv("STORAGE_SERVICE_URL", storageAddr)
	t.Setenv("STORAGE_SERVICE_TLS", "false")
	t.Setenv("STORAGE_KEY", engineTestStorageKeyHex)

	// enclaveHostAddr resolves to loopback for fake enclaves (local processes)
	// and the Nitro wg0 host IP (100.64.0.3) for real enclaves.
	host := enclaveHostAddr()
	t.Setenv("GATEWAY_URL", fmt.Sprintf("http://%s:9998,http://%s:9999", host, host))
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

// cwEngineTestServers holds the engine-test WASM binary server state.
var cwEngineTestServers struct {
	once        sync.Once
	wasmURL     string // URL using host IP (accessible from Docker and host)
	binaryHash  []byte
	artifactDir string // directory containing the binary and config files
	err         error
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
		mux.HandleFunc("/"+engineTestBinaryFilename, func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(encoded))
		})
		mux.HandleFunc("/"+engineTestConfigFilename, func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(configJSON))
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
		cwEngineTestServers.wasmURL = fmt.Sprintf("http://%s:%d/%s", hostIP, port, engineTestBinaryFilename)
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
// enclave: http-actions + consensus/Simple both handled in-process).
//
// Success signals:
//   - "engine-test-secret" + the expected secret value in workflow-DON logs.
//   - "engine-test-http" + status=200 in workflow-DON logs.
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

// startFakeStorageService starts a gRPC NodeService bound to 0.0.0.0 (so the
// enclave can reach it over wg0 in nitro) and returns the address the enclave
// dials it at (enclaveHost:port) plus the service, so the test can set the
// artifact URL once the WASM server is up.
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
	if os.Getenv("REMOTE_ENCLAVE_URLS") != "" {
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
	//    stands up the fake CRE storage service (STORAGE_SERVICE_URL) and sets
	//    STORAGE_KEY; storageSvc's artifact URL is populated once the WASM
	//    server is up (below).
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
	// Each enclave has different PCR values (WireGuard keys baked per CID),
	// so collect all valid measurements. The relay handler accepts a JSON
	// array of PCR objects and tries each until one matches.
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

	// 5. Compile engine-test WASM, serve binary + config, and copy to Docker containers.
	configJSON := fmt.Sprintf(`{"echo_url":%q}`, echoURL)
	wasmURL, configURL, artifactDir, _, initErr := initCWEngineTestServers(configJSON)
	require.NoError(t, initErr, "failed to initialize engine-test WASM server")
	testLogger.Info().Msgf("Engine-test WASM binary served at %s", wasmURL)
	testLogger.Info().Msgf("Engine-test config served at %s", configURL)

	// Point the fake storage service at the (base64) WASM the enclave will fetch.
	// The WASM server binds 0.0.0.0, so the enclave reaches the same port at its
	// enclave-reachable host (wg0 IP for nitro, loopback for fake); swap only the
	// host of wasmURL (which uses the Docker-reachable host IP).
	wasmParsed, perr := url.Parse(wasmURL)
	require.NoError(t, perr, "parsing engine-test WASM URL")
	storageSvc.setURL(fmt.Sprintf("http://%s:%s%s", enclaveHostAddr(), wasmParsed.Port(), wasmParsed.Path))

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

	// The GetSecret path routes through the enclave's gateway client, configured
	// with a dead gateway first (:9998) and the real one second (:9999). The
	// workflow only finishes if every gateway call failed over from the dead
	// proxy to the healthy one. Assert the dead proxy was actually hit, so this
	// test genuinely exercises round-robin failover rather than passing vacuously
	// (e.g. if the cursor logic changed to skip the first URL).
	require.Positive(t, deadGwProxy.Hits(), "dead gateway proxy was never hit; round-robin failover was not exercised")

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

	testLogger.Info().Msg("Engine-path E2E test passed: VaultDON remote dispatch + in-enclave http-actions interception validated")
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

	testLogger.Info().Msgf("Registering confidential workflow (binaryURL=%s, configURL=%s, attributes=%s)", binaryURL, configURL, string(attributes))

	configURLPtr := &configURL
	workflowID, err := creworkflow.RegisterWithContract(
		context.Background(),
		sethClient,
		common.HexToAddress(wfRegistryRef.Address),
		wfRegistryRef.Version,
		0, // donID unused for v2
		testEnv.Dons.MustWorkflowDON().DonFamily,
		"engine-test-confidential",
		binaryURL,
		configURLPtr,
		nil, // no secrets URL
		attributes,
		nil, // keep HTTP URL on-chain; enclave fetches binary via HTTP, syncer file-fetcher extracts filename from URL path
	)
	require.NoError(t, err, "failed to register confidential workflow")
	testLogger.Info().Msgf("Confidential workflow registered: %s", workflowID)

	t.Cleanup(func() {
		testLogger.Info().Msg("Cleaning up confidential workflow...")
		_ = creworkflow.DeleteWithContract(
			context.Background(),
			sethClient,
			common.HexToAddress(wfRegistryRef.Address),
			wfRegistryRef.Version,
			"engine-test-confidential",
		)
	})

	return workflowID
}
