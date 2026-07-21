package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	vaultcommon "github.com/smartcontractkit/chainlink-common/pkg/capabilities/actions/vault"
	capabilitiespb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/pb"
	jsonrpc "github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"
	gateway_common "github.com/smartcontractkit/chainlink-common/pkg/types/gateway"
	capabilities_registry_wrapper_v2 "github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	workflow_registry_v2_wrapper "github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/workflow_registry_wrapper_v2"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	keystone_changeset "github.com/smartcontractkit/chainlink/deployment/keystone/changeset"
	crecontracts "github.com/smartcontractkit/chainlink/system-tests/lib/cre/contracts"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/vault"
	libcrypto "github.com/smartcontractkit/chainlink/system-tests/lib/crypto"
	"github.com/smartcontractkit/chainlink/v2/core/capabilities/vault/vaultutils"
	chainlink_utils "github.com/smartcontractkit/chainlink/v2/core/utils"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/tests"
	creEnvironment "github.com/smartcontractkit/chainlink-confidential-compute/tests/e2e/environment"
	creJob "github.com/smartcontractkit/chainlink-confidential-compute/tests/e2e/job"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink/v2/core/capabilities/vault/vaulttypes"

	crelib "github.com/smartcontractkit/chainlink/system-tests/lib/cre"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment/blockchains/evm"
	envconfig "github.com/smartcontractkit/chainlink/system-tests/lib/cre/environment/config"
	"github.com/smartcontractkit/chainlink/system-tests/tests/smoke/cre"
	systemtests "github.com/smartcontractkit/chainlink/system-tests/tests/test-helpers"
	ttypes "github.com/smartcontractkit/chainlink/system-tests/tests/test-helpers/configuration"
)

const (
	relativePathToRepoRoot = "../../../chainlink"
	workflowOwner          = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	requestCount           = 6
	// interRequestDelay is the delay between consecutive requests,
	// giving key rotation a chance to trigger during the test.
	interRequestDelay = 5 * time.Second
	// workflowTag is a constant used when registering/triggering the workflow.
	workflowTag = "some-tag"
)

type App struct {
	Name             string
	Version          string
	WorkflowPath     string
	GetSecrets       func() (names, values []string)
	GetTriggerInputs func(secretNames []string, owner string) ([]json.RawMessage, error)
	Validate         func(logger zerolog.Logger, bodies [][]byte) error
}

var apps []App = []App{
	{
		Name:             "confidential-http",
		Version:          "1.0.0-alpha",
		WorkflowPath:     "workflow/confidentialhttp/main.go",
		GetSecrets:       getConfidentialHTTPSecrets,
		GetTriggerInputs: getConfidentialHTTPTriggerInputs,
		Validate:         validateRecipientRequests,
	},
}

// dumpDockerLogs dumps the last N lines of logs from all Docker containers.
// Call this from t.Cleanup to capture container logs on test failure.
func dumpDockerLogs(t *testing.T, logger zerolog.Logger, tailLines int) {
	t.Helper()
	if !t.Failed() {
		return
	}
	logger.Warn().Msg("=== DUMPING DOCKER CONTAINER LOGS (test failed) ===")

	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}").CombinedOutput()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to list Docker containers")
		return
	}
	logger.Info().Msgf("Docker containers:\n%s", string(out))

	// Persist raw container logs to logs/docker/<name>.log so they survive
	// testcontainers cleanup and can be uploaded as a CI artifact. The
	// filtered dump below still goes to stdout/test logger as before.
	rawLogDir := filepath.Join("logs", "docker")
	if mkErr := os.MkdirAll(rawLogDir, 0o755); mkErr != nil {
		logger.Warn().Err(mkErr).Str("dir", rawLogDir).Msg("Failed to create raw docker log dir")
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			continue
		}
		containerID := parts[0]
		containerName := parts[1]
		containerImage := ""
		if len(parts) >= 4 {
			containerImage = parts[3]
		}

		// For chainlink node containers, dump workflow-related logs
		isChainlinkNode := strings.Contains(containerImage, "chainlink") ||
			strings.Contains(containerName, "chainlink") ||
			strings.Contains(containerName, "node") ||
			strings.Contains(containerName, "workflow") ||
			strings.Contains(containerName, "bootstrap") ||
			strings.Contains(containerName, "gateway")

		fullLogs, logErr := exec.Command("docker", "logs", containerID).CombinedOutput()
		if logErr != nil {
			logger.Error().Err(logErr).Str("container", containerName).Msg("Failed to get container logs")
			continue
		}

		if writeErr := os.WriteFile(filepath.Join(rawLogDir, containerName+".log"), fullLogs, 0o644); writeErr != nil {
			logger.Warn().Err(writeErr).Str("container", containerName).Msg("Failed to persist raw container logs")
		}

		// Tail in memory for the filtered stdout dump.
		allLines := strings.Split(string(fullLogs), "\n")
		tailFrom := 0
		if len(allLines) > tailLines {
			tailFrom = len(allLines) - tailLines
		}
		logs := []byte(strings.Join(allLines[tailFrom:], "\n"))

		if isChainlinkNode {
			// For CRE nodes, search for workflow/capability execution logs
			logLines := strings.Split(string(logs), "\n")
			var workflowLogs []string
			for _, logLine := range logLines {
				lower := strings.ToLower(logLine)
				if isTelemetryNoise(lower) {
					continue
				}
				if strings.Contains(lower, "workflow") ||
					strings.Contains(lower, "capability") ||
					strings.Contains(lower, "confidential") ||
					strings.Contains(lower, "wasm") ||
					strings.Contains(lower, "engine") ||
					strings.Contains(lower, "trigger") ||
					strings.Contains(lower, "consensus") ||
					strings.Contains(lower, "http-action") ||
					strings.Contains(lower, "http_action") ||
					strings.Contains(lower, "error") ||
					strings.Contains(lower, "err") ||
					strings.Contains(lower, "fail") ||
					strings.Contains(lower, "panic") ||
					strings.Contains(lower, "fatal") {
					workflowLogs = append(workflowLogs, logLine)
				}
			}
			logger.Warn().Str("container", containerName).Str("image", containerImage).
				Int("relevantLines", len(workflowLogs)).Int("totalLines", len(logLines)).
				Msg("CRE node container logs (filtered)")
			// Print each line individually to avoid truncation
			for i, wl := range workflowLogs {
				if i >= 300 { // limit to 300 relevant lines
					logger.Warn().Str("container", containerName).Msgf("... truncated %d more relevant lines", len(workflowLogs)-300)
					break
				}
				logger.Warn().Str("container", containerName).Msg(wl)
			}
		} else {
			// For non-CRE containers, just check for errors
			logLines := strings.Split(string(logs), "\n")
			var errors []string
			for _, logLine := range logLines {
				lower := strings.ToLower(logLine)
				if isTelemetryNoise(lower) {
					continue
				}
				if strings.Contains(lower, "error") || strings.Contains(lower, "fail") || strings.Contains(lower, "panic") {
					errors = append(errors, logLine)
				}
			}
			if len(errors) > 0 {
				logger.Warn().Str("container", containerName).Int("errorLines", len(errors)).Msg("Non-CRE container error logs:")
				for _, el := range errors {
					logger.Warn().Str("container", containerName).Msg(el)
				}
			}
		}
	}
	logger.Warn().Msg("=== END DOCKER CONTAINER LOGS ===")
}

// isTelemetryNoise reports whether a container log line is OTEL/telemetry
// export noise (e.g. failed exports to a collector that isn't running in CI).
// Such lines contain "error" and would otherwise dominate the filtered dump.
func isTelemetryNoise(lowerLine string) bool {
	return strings.Contains(lowerLine, "telemetry error") ||
		strings.Contains(lowerLine, "processor export timeout") ||
		strings.Contains(lowerLine, "go.opentelemetry.io/otel")
}

// Topology files. Used both as CTF_CONFIGS env values and as
// SetupTestEnvironmentWithConfig cache keys (via TestConfig.EnvironmentConfigPath).
// Two top-level tests with the same EnvironmentConfigPath collide in chainlink's
// sharedEnvironments map and re-use a TestEnvironment from a different topology;
// keeping HTTP and engine on distinct paths is what avoids that.
const (
	httpDONConfigFile   = "/configs/workflow-don.toml"
	engineDONConfigFile = "/configs/workflow-don-engine.toml"
)

func getTestConfig(t *testing.T, configPath string) *ttypes.TestConfig {
	t.Helper()

	environmentDirPath := filepath.Join(relativePathToRepoRoot, "core/scripts/cre/environment")

	return &ttypes.TestConfig{
		RelativePathToRepoRoot: relativePathToRepoRoot,
		EnvironmentDirPath:     environmentDirPath,
		EnvironmentConfigPath:  filepath.Join(environmentDirPath, configPath),
		EnvironmentStateFile:   filepath.Join(environmentDirPath, envconfig.StateDirname, envconfig.LocalCREStateFilename),
	}
}

// recipientServer is a test HTTP server that records POSTed request bodies.
// The confidential-http workflow sends its results here so the test can
// validate them.
type recipientServer struct {
	mu       sync.Mutex
	requests [][]byte
	server   *http.Server
	listener net.Listener
	url      string
}

func startRecipientServer(t *testing.T) *recipientServer {
	t.Helper()
	rs := &recipientServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rs.mu.Lock()
		rs.requests = append(rs.requests, body)
		rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	})

	var err error
	rs.listener, err = net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)

	rs.server = &http.Server{Handler: mux}
	go func() {
		if serveErr := rs.server.Serve(rs.listener); serveErr != nil && serveErr != http.ErrServerClosed {
			framework.L.Error().Err(serveErr).Msg("Recipient server error")
		}
	}()

	port := rs.listener.Addr().(*net.TCPAddr).Port
	hostIP := getHostIP()
	rs.url = fmt.Sprintf("http://%s:%d", hostIP, port)
	t.Cleanup(func() { _ = rs.server.Close() })

	framework.L.Info().Msgf("Recipient server started on %s", rs.url)
	return rs
}

func (rs *recipientServer) port() int {
	return rs.listener.Addr().(*net.TCPAddr).Port
}

func (rs *recipientServer) getRequests() [][]byte {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([][]byte, len(rs.requests))
	copy(out, rs.requests)
	return out
}

func (rs *recipientServer) requestCount() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.requests)
}

// sendHTTPTrigger sends one HTTP trigger request to the gateway and retries
// until it gets a successful (non-error) response, indicating the workflow
// has loaded and accepted the trigger.
func sendHTTPTrigger(
	t *testing.T,
	logger zerolog.Logger,
	gatewayURL *url.URL,
	workflowName, workflowID, workflowOwnerAddr string,
	signingKey *ecdsa.PrivateKey,
	input json.RawMessage,
) {
	t.Helper()

	signerAddress := strings.ToLower(crypto.PubkeyToAddress(signingKey.PublicKey).Hex())
	logger.Info().Str("signer", signerAddress).Msg("Sending HTTP trigger request")

	var attempts, rateLimited, notFound, otherErrors int
	start := time.Now()

	triggerPayload := gateway_common.HTTPTriggerRequest{
		Workflow: gateway_common.WorkflowSelector{
			WorkflowOwner: workflowOwnerAddr,
			WorkflowName:  workflowName,
			WorkflowTag:   workflowTag,
			WorkflowID:    workflowID,
		},
		Input: input,
	}
	payloadBytes, err := json.Marshal(triggerPayload)
	require.NoError(t, err)
	rawPayload := json.RawMessage(payloadBytes)

	require.Eventually(t, func() bool {
		attempts++
		req := jsonrpc.Request[json.RawMessage]{
			Version: jsonrpc.JsonRpcVersion,
			Method:  gateway_common.MethodWorkflowExecute,
			Params:  &rawPayload,
			ID:      uuid.New().String(),
		}
		token, tokenErr := chainlink_utils.CreateRequestJWT(req)
		if tokenErr != nil {
			logger.Warn().Err(tokenErr).Msg("Failed to create JWT")
			return false
		}
		tokenString, signErr := token.SignedString(signingKey)
		if signErr != nil {
			logger.Warn().Err(signErr).Msg("Failed to sign JWT")
			return false
		}
		req.Auth = tokenString

		requestBody, marshalErr := json.Marshal(req)
		if marshalErr != nil {
			logger.Warn().Err(marshalErr).Msg("Failed to marshal request")
			return false
		}

		httpReq, reqErr := http.NewRequestWithContext(t.Context(), "POST", gatewayURL.String(), bytes.NewBuffer(requestBody))
		if reqErr != nil {
			logger.Warn().Err(reqErr).Msg("Failed to create trigger request")
			return false
		}
		httpReq.Header.Set("Content-Type", "application/jsonrpc")
		httpReq.Header.Set("Accept", "application/json")

		client := &http.Client{}
		resp, doErr := client.Do(httpReq)
		if doErr != nil {
			logger.Warn().Err(doErr).Int("attempt", attempts).Msg("Trigger request failed")
			return false
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)

		var finalResponse jsonrpc.Response[json.RawMessage]
		_ = json.Unmarshal(body, &finalResponse)

		switch {
		case resp.StatusCode == http.StatusTooManyRequests || (finalResponse.Error != nil && finalResponse.Error.Code == jsonrpc.ErrLimitExceeded):
			rateLimited++
			logger.Warn().Int("attempt", attempts).Int("rateLimited", rateLimited).Dur("elapsed", time.Since(start)).Msg("Rate limited by gateway (per-workflow limit: burst=3, rate=1/30s)")
			return false
		case finalResponse.Error != nil && strings.Contains(finalResponse.Error.Error(), "Workflow not found"):
			notFound++
			logger.Info().Int("attempt", attempts).Int("notFound", notFound).Msg("Workflow not yet registered in gateway")
			return false
		case resp.StatusCode != http.StatusOK || finalResponse.Error != nil:
			otherErrors++
			logger.Warn().Int("attempt", attempts).Int("status", resp.StatusCode).Str("body", string(body)).Msg("Trigger request got unexpected error")
			return false
		default:
			logger.Info().Int("attempt", attempts).Int("rateLimited", rateLimited).Int("notFound", notFound).Int("otherErrors", otherErrors).Dur("elapsed", time.Since(start)).Msg("Trigger ACCEPTED")
			return true
		}
	}, 5*time.Minute, 5*time.Second, "gateway should accept trigger")
}

// requireE2EEnvVars skips the test unless the e2e harness env vars are set.
func requireE2EEnvVars(t *testing.T) {
	t.Helper()
	for _, envVar := range []string{"CI", "CTF_CONFIGS", "CTF_JD_IMAGE", "CTF_CHAINLINK_IMAGE"} {
		if os.Getenv(envVar) == "" {
			t.Skipf("Skipping test: required environment variable %s is not set", envVar)
		}
	}
}

// nukeDockerState removes all containers and all volumes on the host. CTF's
// own RemoveTestContainers only targets framework=ctf-labeled containers and
// silently fails to remove testcontainers-managed postgres volumes still in
// use; that residue carries stale CRE state into the next sequential test.
// Registered as t.Cleanup at the start of each top-level e2e test so the
// next test sees a clean docker daemon.
func nukeDockerState(testLogger zerolog.Logger) {
	cmd := exec.Command("bash", "-c",
		"docker ps -aq | xargs -r docker rm -f 2>/dev/null; "+
			"docker volume ls -q | xargs -r docker volume rm 2>/dev/null")
	if err := cmd.Run(); err != nil {
		testLogger.Warn().Err(err).Msg("docker cleanup encountered errors (non-fatal)")
	}
}

// TestConfidentialHTTPE2E exercises the HTTP-trigger path end-to-end:
// gateway -> CRE workflow -> confidential-http capability -> Nitro enclave.
// Top-level peer of TestConfidentialWorkflowsEngineE2E so the two run in
// separate testing.T contexts without sharing function-local state.
func TestConfidentialHTTPE2E(t *testing.T) {
	var testLogger = framework.L
	requireE2EEnvVars(t)
	t.Cleanup(func() { nukeDockerState(testLogger) })

	// In the case of testing against prior release versions, we use the PRIOR_VERSION_BINARY_PATHS to override our current capability binaries
	// with capability binaries from a prior release. This ensures we do not introduce enclave changes that break our E2E functionality.
	// Parse PRIOR_VERSION_BINARY_PATHS env var (format: "app1:path1,app2:path2")
	priorVersionPaths := make(map[string]string)
	if priorPathsEnv := os.Getenv("PRIOR_VERSION_BINARY_PATHS"); priorPathsEnv != "" {
		for _, pair := range strings.Split(priorPathsEnv, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				priorVersionPaths[parts[0]] = parts[1]
				testLogger.Info().Msgf("Using prior version binary for %s: %s", parts[0], parts[1])
			}
		}
	}

	for _, app := range apps {
		// Skip building if using a prior version binary
		if priorPath, usePrior := priorVersionPaths[app.Name]; usePrior {
			testLogger.Info().Msgf("Skipping build for %s, using prior version from: %s", app.Name, priorPath)
			continue
		}

		capabilityName := app.Name
		projectPath := "../../enclave/apps/" + capabilityName + "/capability" + "/cmd/" + capabilityName
		outputBinary := "binaries/" + capabilityName
		absoluteBinaryPath, err := filepath.Abs(outputBinary)
		require.NoError(t, err)

		targetArch := runtime.GOARCH
		testLogger.Info().Msgf("Building capability binary for %s architecture...", targetArch)
		cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", absoluteBinaryPath)
		cmd.Dir = projectPath
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH="+targetArch)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "failed to build capability binary: %s", string(output))
		testLogger.Info().Msgf("Capability binary built successfully")
	}

	for _, app := range apps {
		t.Run(fmt.Sprintf("Testing %s", app.Name), func(t *testing.T) {
			testLogger.Info().Msgf("Provisioning enclave for app: %s", app.Name)
			enclaveType := types.EnclaveTypeNitro
			if tests.UseFakeEnclave() {
				enclaveType = types.EnclaveTypeFake
			}

			var enclaves []types.Enclave
			var configURLs []string
			var enclaveCleanups []func()
			if os.Getenv("REMOTE_ENCLAVE_URLS") != "" && os.Getenv("PCR_MEASUREMENTS_FILE") != "" {
				mBytes, err := os.ReadFile(os.Getenv("PCR_MEASUREMENTS_FILE"))
				require.NoError(t, err, "failed to read PCR measurements file")
				var pcrMeasurements nitro.Measurements
				err = json.Unmarshal(mBytes, &pcrMeasurements)
				require.NoError(t, err, "failed to unmarshal PCR measurements")
				testLogger.Info().Msgf("Using remote enclaves with PCR measurements: %+v", pcrMeasurements)
				mBytes, err = json.Marshal(pcrMeasurements.Measurements)
				require.NoError(t, err, "failed to re-marshal PCR measurements")

				remoteEnclaveURLs := strings.Split(os.Getenv("REMOTE_ENCLAVE_URLS"), ",")
				remoteConfigURLs := remoteEnclaveURLs
				if os.Getenv("REMOTE_ENCLAVE_CONFIG_URLS") != "" {
					remoteConfigURLs = strings.Split(os.Getenv("REMOTE_ENCLAVE_CONFIG_URLS"), ",")
					require.Equal(t, len(remoteEnclaveURLs), len(remoteConfigURLs), "REMOTE_ENCLAVE_URLS and REMOTE_ENCLAVE_CONFIG_URLS must have the same number of entries")
				}

				for i, enclaveURL := range remoteEnclaveURLs {
					enclaveURL = strings.TrimSpace(enclaveURL)
					configURL := strings.TrimSpace(remoteConfigURLs[i])
					testLogger.Info().Msgf("Adding remote enclave %d: %s (config: %s)", i, enclaveURL, configURL)
					enclaves = append(enclaves, types.Enclave{
						EnclaveType:      enclaveType,
						EnclaveExtraData: []byte{},
						EnclaveID:        [32]byte{uint8(i + 1)},
						TrustedValues:    [][]byte{mBytes},
						EnclaveURL:       enclaveURL,
						Region:           "us-west-2",
					})
					configURLs = append(configURLs, configURL)
				}
			} else {
				testLogger.Info().Msgf("Starting local enclave for app: %s", app.Name)
				rootDir, err := util.GetRepoRoot()
				require.NoError(t, err)

				// Check if we should use a prior version binary
				if priorPath, usePrior := priorVersionPaths[app.Name]; usePrior {
					// Copy prior version binary to expected location
					testLogger.Info().Msgf("Using prior version binary from: %s", priorPath)
					destPath := filepath.Join(rootDir, "tests", "e2e", "binaries", app.Name)
					copyCmd := exec.Command("cp", priorPath, destPath)
					if output, err := copyCmd.CombinedOutput(); err != nil {
						require.NoError(t, err, "failed to copy prior version binary: %s", string(output))
					}
				}
				baseCID := 16
				httpPorts := []string{"8080", "8081"}
				configHttpPorts := []string{"8082", "8083"}

				// Clean up any stale processes on ports before starting.
				testLogger.Info().Msgf("Cleaning up stale processes on ports...")
				for i := range httpPorts {
					tests.KillProcessOnPort(t, httpPorts[i])
					tests.KillProcessOnPort(t, configHttpPorts[i])
				}

				for i := range httpPorts {
					enclaveCID := strconv.Itoa(baseCID + i)
					enclaveName := fmt.Sprintf("go-enclave-%s-%d", app.Name, i)
					isFirstEnclave := i == 0

					cleanup := tests.MustSetupEnclave(
						t, rootDir, enclaveCID,
						httpPorts[i], configHttpPorts[i],
						app.Name, enclaveName, isFirstEnclave,
					)
					enclaveCleanups = append(enclaveCleanups, cleanup)

					measurements, err := tests.EnsureEnclaveAndGetMeasurements(baseCID + i)
					require.NoError(t, err, "Failed to get enclave measurements")

					hostIP := getHostIP()
					testLogger.Info().Msgf("Using host IP: %s for enclave communication", hostIP)
					// Proxy our enclaves to ensure the correct API key is used.
					enclaveURL := fmt.Sprintf("http://%s:%s", hostIP, httpPorts[i])
					if i == 0 {
						proxyURL, proxyCleanup := startProxy(t, enclaveURL, testLogger)
						defer proxyCleanup()
						testLogger.Info().Msgf("Started proxy for enclave 0 at %s forwarding to %s", proxyURL, enclaveURL)
						enclaveURL = proxyURL
					}

					enclaves = append(enclaves, types.Enclave{
						EnclaveType:      enclaveType,
						EnclaveExtraData: []byte{},
						EnclaveID:        [32]byte{uint8(i + 1)},
						TrustedValues:    [][]byte{[]byte("invalid"), measurements}, // ensures we can handle multiple trusted values
						EnclaveURL:       enclaveURL,
						Region:           "us-west-2",
					})
					configURLs = append(configURLs, fmt.Sprintf("http://localhost:%s", configHttpPorts[i]))
				}
				// Defer cleanup of all enclaves that haven't been stopped yet
				defer func() {
					for _, cleanup := range enclaveCleanups {
						cleanup()
					}
				}()
			}
			confhttpCap, err := creJob.New(app.Name, app.Version, app.Name, enclaves)
			require.NoError(t, err, "failed to create confidential-http capability job")

			// Register Docker log dumping as the FIRST cleanup so it runs LAST
			// (cleanups run in reverse order). This ensures we capture logs
			// from all CRE containers before they are removed.
			t.Cleanup(func() { dumpDockerLogs(t, testLogger, 500) })

			// Start recipient server BEFORE the CRE environment so its port
			// can be added to the gateway's outbound-proxy whitelist.
			testLogger.Info().Msgf("Starting recipient server...")
			recipient := startRecipientServer(t)

			testLogger.Info().Msgf("Initializing test environment...")
			names, secretValues := app.GetSecrets()
			testEnv := mustInitializeCapabilitySetup(
				t,
				httpDONConfigFile,
				configURLs,
				[]crelib.InstallableCapability{confhttpCap},
				nil, // afterSetup
				[]int{recipient.port()},
				testLogger,
				names,
				secretValues,
				workflowOwner,
			)

			testLogger.Info().Msgf("Generating signing key pair for HTTP trigger...")
			publicKeyAddr, signingKey, newKeysErr := libcrypto.GenerateNewKeyPair()
			require.NoError(t, newKeysErr, "failed to generate signing key pair")

			testLogger.Info().Msgf("Deploying confidential-http workflow...")
			uniqueWorkflowName := "confhttp-" + uuid.New().String()[:8]
			httpWorkflowConfig := &systemtests.HTTPWorkflowConfig{
				AuthorizedKey: publicKeyAddr,
				URL:           recipient.url + "/orders",
			}
			testLogger.Info().Msgf("Workflow config: AuthorizedKey=%s, URL=%s", publicKeyAddr, httpWorkflowConfig.URL)
			workflowID := systemtests.CompileAndDeployWorkflow(t, testEnv, testLogger, uniqueWorkflowName, httpWorkflowConfig, app.WorkflowPath)

			// Determine gateway URL for trigger requests
			gatewayConfig := testEnv.Dons.GatewayConnectors.Configurations[0].Incoming
			gatewayURL, err := url.Parse(
				gatewayConfig.Protocol + "://" + gatewayConfig.Host + ":" +
					strconv.Itoa(gatewayConfig.ExternalPort) + gatewayConfig.Path,
			)
			require.NoError(t, err, "failed to parse gateway URL")

			require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain type")
			workflowOwnerKey := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient.MustGetRootPrivateKey()
			workflowOwnerAddr := strings.ToLower(crypto.PubkeyToAddress(workflowOwnerKey.PublicKey).Hex())

			triggerInputs, err := app.GetTriggerInputs(names, workflowOwner)
			require.NoError(t, err, "failed to build trigger inputs")
			totalTriggers := requestCount * len(triggerInputs)
			// RunInNodeMode causes each workflow node to independently POST
			// to the recipient, so we expect numNodes * totalTriggers results.
			var numNodes int
			for _, nodeSet := range testEnv.Config.NodeSets {
				if nodeSet.Name == "workflow" {
					numNodes = nodeSet.Nodes
					break
				}
			}
			require.NotZero(t, numNodes, "workflow nodeset not found in config")
			totalExpected := totalTriggers * numNodes
			testLogger.Info().Msgf("Sending %d total triggers (%d rounds x %d inputs, expecting %d results with %d nodes, interRequestDelay=%s)...", totalTriggers, requestCount, len(triggerInputs), totalExpected, numNodes, interRequestDelay)
			triggersSent := 0
			for i := range requestCount {
				if i > 0 {
					testLogger.Info().Msgf("Waiting %s before next request to exercise key rotation...", interRequestDelay)
					time.Sleep(interRequestDelay)
				}
				for _, input := range triggerInputs {
					sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
					triggersSent++
					testLogger.Info().Msgf("Trigger %d/%d ACCEPTED, recipient has %d results so far", triggersSent, totalTriggers, recipient.requestCount())
				}
			}

			testLogger.Info().Msgf("All %d triggers accepted, waiting for %d results at recipient server (currently have %d)...", triggersSent, totalExpected, recipient.requestCount())
			require.Eventually(t, func() bool {
				count := recipient.requestCount()
				testLogger.Info().Msgf("Recipient progress: %d/%d results received", count, totalExpected)
				return count >= totalExpected
			}, 5*time.Minute, 5*time.Second, "recipient should receive all workflow results")

			testLogger.Info().Msgf("Validating recipient requests...")
			err = app.Validate(framework.L, recipient.getRequests())
			require.NoError(t, err, "recipient request validation failed")

			// --- Error handling sub-tests ---
			// These exercise the enclave app's error-to-response conversion
			// for DNS failures and upstream timeouts. Results are POSTed to
			// the same recipient server (workflow config is fixed at deploy time).
			useLegacyEnclaves := os.Getenv("REMOTE_ENCLAVE_URLS") != "" && os.Getenv("PCR_MEASUREMENTS_FILE") != ""

			// Rotate a node out of the DON and back in, asserting the executor
			// reconfigures every enclave's signer set to follow DON membership and
			// that requests keep succeeding throughout. Runs before the failover
			// block (which tears down an enclave) and restores the full node set so
			// later sub-tests still see the original topology.
			t.Run("DON node rotation reconfigures enclaves", func(t *testing.T) {
				if useLegacyEnclaves {
					t.Skip("skipping: legacy/remote enclaves are not reconfigured by the executor")
				}
				if _, usePrior := priorVersionPaths[app.Name]; usePrior {
					t.Skip("skipping: prior-version capability binary lacks the config-update proposal path")
				}

				originalNodes := getWorkflowDONNodes(t, testEnv)
				require.GreaterOrEqual(t, len(originalNodes), 4, "need >=4 nodes so dropping one keeps OCR fault tolerance (2F+1)")
				reducedNodes := append([][32]byte{}, originalNodes[:len(originalNodes)-1]...)

				// Always restore the full node set when this subtest finishes, even on
				// failure, so a wedged/partial rotation can't degrade the DON for later
				// subtests. defer (not t.Cleanup) runs before the test context is canceled.
				defer setWorkflowDONNodes(t, testEnv, originalNodes, testLogger)

				// The enclaves require the x-api-key header (matching job.go's "foobar");
				// attach it so direct /publicKeys reads aren't rejected with 401.
				authedEnclaves := make([]types.Enclave, len(enclaves))
				copy(authedEnclaves, enclaves)
				for i := range authedEnclaves {
					authedEnclaves[i].EnclaveAuthHeader = "x-api-key: foobar"
				}

				sendRound := func() {
					for _, input := range triggerInputs {
						sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
					}
				}

				rotate := func(phase string, nodes [][32]byte, expectedSigners [][32]byte) {
					recipient.mu.Lock()
					recipient.requests = nil
					recipient.mu.Unlock()

					testLogger.Info().Str("phase", phase).Int("nodeCount", len(nodes)).Msg("Updating workflow DON node set")
					setWorkflowDONNodes(t, testEnv, nodes, testLogger)
					testLogger.Info().Msg("Waiting 30s for nodes to pick up the new DON membership")
					time.Sleep(30 * time.Second)

					// Triggering drives EnsureFreshEnclaves on each node, which proposes
					// the new signed enclave config.
					sendRound()
					expected := len(nodes) * len(triggerInputs)
					require.Eventually(t, func() bool {
						return recipient.requestCount() >= expected
					}, 5*time.Minute, 5*time.Second, "all %d nodes should deliver during %s", len(nodes), phase)

					assertEnclaveSignersConverge(t, authedEnclaves, expectedSigners, testLogger)
					require.NoError(t, app.Validate(framework.L, recipient.getRequests()), "validation failed during %s", phase)
				}

				rotate("node removal", reducedNodes, reducedNodes)
				rotate("node restoration", originalNodes, originalNodes)
			})

			t.Run("DNS NXDOMAIN returns 400", func(t *testing.T) {
				// Reset recipient to isolate this sub-test's results
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				dnsInput, err := getConfidentialHTTPDNSFailureInput(names, workflowOwner)
				require.NoError(t, err, "failed to build DNS failure input")

				sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, dnsInput)

				dnsExpected := numNodes // one trigger, each node POSTs
				testLogger.Info().Msgf("DNS test: waiting for %d results...", dnsExpected)
				require.Eventually(t, func() bool {
					return recipient.requestCount() >= dnsExpected
				}, 3*time.Minute, 5*time.Second, "DNS failure results should arrive at recipient")

				err = validateDNSFailureResponse(testLogger, recipient.getRequests())
				require.NoError(t, err, "DNS failure response validation failed")
				testLogger.Info().Msg("DNS NXDOMAIN sub-test passed")
			})

			t.Run("upstream timeout returns 504", func(t *testing.T) {
				// Reset recipient to isolate this sub-test's results
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				// Use a public endpoint that delays longer than TimeoutMs (500ms)
				// so the restricted HTTP client triggers a context.DeadlineExceeded → 504.
				timeoutInput, err := getConfidentialHTTPTimeoutInput("https://postman-echo.com/delay/10", names, workflowOwner)
				require.NoError(t, err, "failed to build timeout input")

				sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, timeoutInput)

				timeoutExpected := numNodes
				testLogger.Info().Msgf("Timeout test: waiting for %d results...", timeoutExpected)
				require.Eventually(t, func() bool {
					return recipient.requestCount() >= timeoutExpected
				}, 3*time.Minute, 5*time.Second, "timeout results should arrive at recipient")

				err = validateTimeoutResponse(testLogger, recipient.getRequests())
				require.NoError(t, err, "timeout response validation failed")
				testLogger.Info().Msg("Upstream timeout sub-test passed")
			})

			t.Run("SSRF private address returns 400", func(t *testing.T) {
				if useLegacyEnclaves {
					t.Skip("skipping: legacy/remote enclaves lack the SSRF-blocked-to-400 handling")
				}

				// Reset recipient to isolate this sub-test's results
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				ssrfInput, err := getConfidentialHTTPSSRFBlockedInput(names, workflowOwner)
				require.NoError(t, err, "failed to build SSRF blocked input")

				sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, ssrfInput)

				ssrfExpected := numNodes // one trigger, each node POSTs
				testLogger.Info().Msgf("SSRF test: waiting for %d results...", ssrfExpected)
				require.Eventually(t, func() bool {
					return recipient.requestCount() >= ssrfExpected
				}, 3*time.Minute, 5*time.Second, "SSRF blocked results should arrive at recipient")

				err = validateSSRFBlockedResponse(testLogger, recipient.getRequests())
				require.NoError(t, err, "SSRF blocked response validation failed")
				testLogger.Info().Msg("SSRF private address sub-test passed")
			})

			t.Run("zeroed enclave config is routed around and recovers", func(t *testing.T) {
				if useLegacyEnclaves {
					t.Skip("skipping: remote/legacy enclaves cannot be reconfigured by the test")
				}
				if len(configURLs) < 2 {
					t.Skip("skipping: need >=2 enclaves so one can be zeroed while another serves")
				}

				// Reset recipient to isolate this sub-test's results.
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				// Snapshot a healthy peer's config so we can restore enclave 0 later.
				// Reading the live config (rather than recomputing it) keeps us in sync
				// with any signer re-ordering the node-rotation sub-test applied.
				peer := enclaves[1]
				peer.EnclaveAuthHeader = "x-api-key: foobar"
				savedConfig, err := fetchEnclaveConfig(peer)
				require.NoError(t, err, "failed to read peer enclave config")
				require.False(t, savedConfig.IsZero(), "peer enclave should have a valid config to restore from")

				// Wipe enclave 0's config. /publicKeys now returns 503, so the client
				// pool marks it dead and routes around it; requests must keep succeeding
				// on the remaining enclave, the same resilience as the fallback path.
				postEnclaveConfig(t, configURLs[0], types.EnclaveConfig{})
				testLogger.Info().Msg("Zeroed enclave 0 config; waiting 15s for the pool to mark it dead")
				time.Sleep(15 * time.Second)

				require.NotEmpty(t, triggerInputs, "expected at least one trigger input")
				for _, input := range triggerInputs {
					sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
				}
				expected := numNodes * len(triggerInputs)
				require.Eventually(t, func() bool {
					count := recipient.requestCount()
					testLogger.Info().Msgf("Zeroed-config sub-test recipient progress: %d/%d", count, expected)
					return count >= expected
				}, 3*time.Minute, 5*time.Second, "requests should keep succeeding while enclave 0 is unconfigured")
				require.NoError(t, app.Validate(framework.L, recipient.getRequests()), "validation failed while enclave 0 was unconfigured")

				// Restore enclave 0 and confirm it recovers back into rotation.
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()
				postEnclaveConfig(t, configURLs[0], savedConfig)
				testLogger.Info().Msg("Restored enclave 0 config; waiting 15s for the pool to bring it back")
				time.Sleep(15 * time.Second)

				for _, input := range triggerInputs {
					sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
				}
				require.Eventually(t, func() bool {
					count := recipient.requestCount()
					testLogger.Info().Msgf("Recovery sub-test recipient progress: %d/%d", count, expected)
					return count >= expected
				}, 3*time.Minute, 5*time.Second, "requests should keep succeeding after enclave 0 recovers")
				require.NoError(t, app.Validate(framework.L, recipient.getRequests()), "validation failed after enclave 0 recovered")
			})

			t.Run("capability-registry measurement update still succeeds via fallback", func(t *testing.T) {
				// Reset recipient to isolate this sub-test's results.
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				// Push nonsense trusted measurements to the capability registry config.
				// The running workflow nodes should still succeed by falling back to prior
				// trusted measurements stored in memory by the enclave client pool.
				poisonedEnclaves := make([]types.Enclave, len(enclaves))
				copy(poisonedEnclaves, enclaves)
				for i := range poisonedEnclaves {
					poisonedEnclaves[i].TrustedValues = [][]byte{[]byte("nonsense-measurement")}
				}
				updateCapabilityRegistryEnclaveMeasurements(t, testEnv, app.Name, app.Version, poisonedEnclaves, testLogger)
				testLogger.Info().Msg("Waiting 10s for workflow nodes to detect updated registry config")
				time.Sleep(10 * time.Second)

				require.NotEmpty(t, triggerInputs, "expected at least one trigger input")
				for _, input := range triggerInputs {
					sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
				}

				expected := numNodes * len(triggerInputs)
				require.Eventually(t, func() bool {
					count := recipient.requestCount()
					testLogger.Info().Msgf("Fallback sub-test recipient progress: %d/%d", count, expected)
					return count >= expected
				}, 3*time.Minute, 5*time.Second, "recipient should receive successful responses after registry trusted value update")

				err := app.Validate(framework.L, recipient.getRequests())
				require.NoError(t, err, "recipient validation failed after registry trusted value update")
			})

			// Test enclave failover: take down the first enclave and verify requests still succeed.
			if len(enclaveCleanups) > 1 {
				testLogger.Info().Msgf("Taking down first enclave to test failover...")
				enclaveCleanups[0]()
				enclaveCleanups = enclaveCleanups[1:]

				// The enclave pool refreshes health every 10 seconds. Waiting exactly
				// one interval races the refresh on some nodes, allowing the first
				// request to select the enclave while it is still marked healthy.
				testLogger.Info().Msg("Waiting 20s for every node's enclave pool to observe the stopped enclave")
				time.Sleep(20 * time.Second)

				// Reset recipient for failover validation
				recipient.mu.Lock()
				recipient.requests = nil
				recipient.mu.Unlock()

				testLogger.Info().Msgf("Sending requests with one enclave down to verify failover...")
				failoverTriggers := 0
				for i := range requestCount {
					if i > 0 {
						time.Sleep(interRequestDelay)
					}
					for _, input := range triggerInputs {
						sendHTTPTrigger(t, testLogger, gatewayURL, uniqueWorkflowName, workflowID, workflowOwnerAddr, signingKey, input)
						failoverTriggers++
						testLogger.Info().Msgf("Failover trigger %d/%d ACCEPTED, recipient has %d results", failoverTriggers, totalTriggers, recipient.requestCount())
					}
				}

				failoverExpected := failoverTriggers * numNodes
				testLogger.Info().Msgf("Failover: waiting for %d results (currently have %d)...", failoverExpected, recipient.requestCount())
				require.Eventually(t, func() bool {
					count := recipient.requestCount()
					testLogger.Info().Msgf("Failover recipient progress: %d/%d results received", count, failoverExpected)
					return count >= failoverExpected
				}, 5*time.Minute, 5*time.Second, "recipient should receive results after failover")

				err = app.Validate(framework.L, recipient.getRequests())
				require.NoError(t, err, "recipient validation failed after failover")
				testLogger.Info().Msgf("Enclave failover test passed successfully")
			}
		})
	}

}

// TestConfidentialWorkflowsEngineE2E exercises the workflow-engine path:
// syncer -> ConfidentialModule -> confidential-workflows capability -> Nitro
// enclave. Top-level peer of TestConfidentialHTTPE2E. Skipped under LOAD_TEST.
func TestConfidentialWorkflowsEngineE2E(t *testing.T) {
	var testLogger = framework.L
	requireE2EEnvVars(t)
	if os.Getenv("LOAD_TEST") == "true" {
		t.Skip("engine test does not run in load-test mode")
	}
	t.Cleanup(func() { nukeDockerState(testLogger) })

	buildLocalBinaries := func() error {
		projectPath := "../../enclave/apps/confidential-workflows/capability/cmd/confidential-workflows"
		outputBinary := "binaries/confidential-workflows"
		absoluteBinaryPath, err := filepath.Abs(outputBinary)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}
		targetArch := runtime.GOARCH
		testLogger.Info().Msgf("Building local capability binary confidential-workflows for %s...", targetArch)
		cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", absoluteBinaryPath)
		cmd.Dir = projectPath
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH="+targetArch)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to build confidential-workflows binary: %s", string(output))
		}
		testLogger.Info().Msgf("Local capability binary confidential-workflows built successfully")
		return nil
	}
	testConfidentialWorkflowsEngine(t, testLogger, buildLocalBinaries)
}

func mustInitializeCapabilitySetup(
	t *testing.T,
	configPath string,
	configURLs []string,
	capabilities []crelib.InstallableCapability,
	afterSetup func() error,
	extraAllowedPorts []int,
	testLogger zerolog.Logger,
	secretNames []string,
	secretValues []string,
	secretOwner string,
	extraFeatures ...crelib.Feature,
) (testEnv *ttypes.TestEnvironment) {
	testLogger.Info().Msgf("Setting up CRE environment...")
	require.NoError(t, creEnvironment.StartCreEnvironment(context.Background(), relativePathToRepoRoot, capabilities, afterSetup, extraAllowedPorts, extraFeatures...))

	testLogger.Info().Msgf("Setting up test environment...")
	time.Sleep(3 * time.Second)
	testEnv = systemtests.SetupTestEnvironmentWithConfig(t, getTestConfig(t, configPath))

	workflowRegistryAddress := crecontracts.MustGetAddressFromDataStore(testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(), //nolint:staticcheck // SA1019 ignoring deprecation warning for this usage
		keystone_changeset.WorkflowRegistry.String(), testEnv.CreEnvironment.ContractVersions[keystone_changeset.WorkflowRegistry.String()], "")
	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain type")

	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient
	systemtests.CompileAndDeployWorkflow(t, testEnv, testLogger, "consensustest", &systemtests.None{}, relativePathToRepoRoot+"/core/scripts/cre/environment/examples/workflows/node-mode/main.go")
	wfRegistryContract, err := workflow_registry_v2_wrapper.NewWorkflowRegistry(common.HexToAddress(workflowRegistryAddress), sethClient.Client)
	require.NoError(t, err, "failed to get workflow registry contract wrapper")

	testLogger.Info().Msgf("Ensuring DKG result packages are present...")
	require.Eventually(t, func() bool {
		for _, nodeSet := range testEnv.Config.NodeSets {
			var vaultFound bool
			for _, cap := range nodeSet.Capabilities {
				if cap == crelib.VaultCapability {
					vaultFound = true
					break
				}
			}
			if vaultFound {
				for i, node := range nodeSet.NodeSpecs {
					if !slices.Contains(node.Roles, crelib.BootstrapNode) {
						packageCount, err := vault.GetResultPackageCount(t.Context(), i, nodeSet.DbInput.Port)
						if err != nil || packageCount != 1 {
							return false
						}
					}
				}
				return true
			}
		}
		return false
	}, time.Second*300, time.Second*5)

	testLogger.Info().Msgf("Sleeping for 120 seconds to allow environment to settle...")
	time.Sleep(120 * time.Second)

	testLogger.Info().Msgf("Fetching P2P IDs...")
	var p2pIDs [][]byte
	workers, err := testEnv.Dons.MustWorkflowDON().Workers()
	require.NoError(t, err, "failed to get worker nodes from topology")
	for _, node := range workers {
		p2pIDs = append(p2pIDs, node.Keys.P2PKey.PeerID[:])
	}
	testLogger.Info().Msgf("P2P IDs: %v", p2pIDs)

	testLogger.Info().Msgf("Fetching Vault DON Public Key...")
	gatewayURL, err := url.Parse(
		testEnv.Dons.GatewayConnectors.Configurations[0].Incoming.Protocol +
			"://" + testEnv.Dons.GatewayConnectors.Configurations[0].Incoming.Host +
			":" + strconv.Itoa(testEnv.Dons.GatewayConnectors.Configurations[0].Incoming.ExternalPort) +
			testEnv.Dons.GatewayConnectors.Configurations[0].Incoming.Path,
	)
	require.NoError(t, err, "failed to parse gateway URL")
	vaultPublicKey := cre.FetchVaultPublicKey(t, gatewayURL.String())
	testLogger.Info().Msgf("Vault Public Key: %s", vaultPublicKey)

	testLogger.Info().Msgf("Storing secret in Vault...")
	mustStoreEnclaveSecrets(t, gatewayURL, vaultPublicKey, secretNames, secretValues, secretOwner, func() *bind.TransactOpts { return sethClient.NewTXOpts() }, wfRegistryContract)

	// Legacy/remote enclaves boot with a deliberately misaligned signer set so
	// they exercise the boot-then-set-config auto-update path; local enclaves
	// boot aligned so the other sub-tests run against a settled config.
	useLegacyEnclaves := os.Getenv("REMOTE_ENCLAVE_URLS") != "" && os.Getenv("PCR_MEASUREMENTS_FILE") != ""
	testLogger.Info().Msgf("Configuring enclaves...")
	for i := range configURLs {
		// workflow-don.toml is a 4-node DON with F=1. Pass don.F here;
		// setEnclaveConfig derives the enclave's F = 2*don.F to match the
		// relay-DON quorum (see the note there).
		setEnclaveConfig(t, configURLs[i], p2pIDs, vaultPublicKey, 1, useLegacyEnclaves)
	}

	return testEnv
}

func updateCapabilityRegistryEnclaveMeasurements(
	t *testing.T,
	testEnv *ttypes.TestEnvironment,
	capabilityName string,
	capabilityVersion string,
	enclaves []types.Enclave,
	testLogger zerolog.Logger,
) {
	t.Helper()

	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain type")
	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient

	capabilityRegistryAddress := crecontracts.MustGetAddressFromDataStore(
		testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(), //nolint:staticcheck // SA1019 ignoring deprecation warning for this usage
		keystone_changeset.CapabilitiesRegistry.String(),
		testEnv.CreEnvironment.ContractVersions[keystone_changeset.CapabilitiesRegistry.String()],
		"",
	)

	capReg, err := capabilities_registry_wrapper_v2.NewCapabilitiesRegistry(common.HexToAddress(capabilityRegistryAddress), sethClient.Client)
	require.NoError(t, err, "failed to construct capabilities registry client")

	donName := "workflow-don"
	donInfo, err := capReg.GetDONByName(&bind.CallOpts{}, donName)
	require.NoError(t, err, "failed to fetch workflow DON info")

	wrappedConfig, err := values.WrapMap(types.EnclavesList{Enclaves: enclaves})
	require.NoError(t, err, "failed to wrap updated enclaves config")

	// Build a fresh CapabilityConfig with only DefaultConfig set.
	// We avoid unmarshal-modify-remarshal of existing bytes because prior
	// broken test runs may have left corrupted config on-chain.
	newCfg := &capabilitiespb.CapabilityConfig{
		DefaultConfig: values.Proto(wrappedConfig).GetMapValue(),
	}
	updatedConfigBytes, err := proto.Marshal(newCfg)
	require.NoError(t, err, "failed to marshal updated CapabilityConfig")

	targetCapabilityID := capabilityName + "@" + capabilityVersion
	updatedCapConfigs := make([]capabilities_registry_wrapper_v2.CapabilitiesRegistryCapabilityConfiguration, len(donInfo.CapabilityConfigurations))
	found := false
	for i, capCfg := range donInfo.CapabilityConfigurations {
		if capCfg.CapabilityId == targetCapabilityID || strings.HasPrefix(capCfg.CapabilityId, capabilityName+"@") {
			capCfg.Config = updatedConfigBytes
			found = true
		}
		updatedCapConfigs[i] = capCfg
	}
	require.True(t, found, "failed to find capability config for %s in DON %s", targetCapabilityID, donInfo.Name)

	updateParams := capabilities_registry_wrapper_v2.CapabilitiesRegistryUpdateDONParams{
		Name:                     donInfo.Name,
		Config:                   donInfo.Config,
		CapabilityConfigurations: updatedCapConfigs,
		Nodes:                    donInfo.NodeP2PIds,
		F:                        donInfo.F,
		IsPublic:                 donInfo.IsPublic,
	}

	tx, err := capReg.UpdateDONByName(sethClient.NewTXOpts(), donName, updateParams)
	require.NoError(t, err, "failed to update DON capability configuration")

	testLogger.Info().Str("txHash", tx.Hash().Hex()).Str("donName", donName).Str("capability", targetCapabilityID).Msg("Submitted DON capability config update with poisoned trusted measurements")
	_, err = bind.WaitMined(t.Context(), sethClient.Client, tx)
	require.NoError(t, err, "failed waiting for DON update transaction to be mined")
}

// mustWorkflowCapReg builds a capabilities-registry client bound to the deployed registry.
func mustWorkflowCapReg(t *testing.T, testEnv *ttypes.TestEnvironment) *capabilities_registry_wrapper_v2.CapabilitiesRegistry {
	t.Helper()
	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain type")
	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient
	addr := crecontracts.MustGetAddressFromDataStore(
		testEnv.CreEnvironment.CldfEnvironment.DataStore,
		testEnv.CreEnvironment.Blockchains[0].ChainSelector(), //nolint:staticcheck // SA1019 ignoring deprecation warning for this usage
		keystone_changeset.CapabilitiesRegistry.String(),
		testEnv.CreEnvironment.ContractVersions[keystone_changeset.CapabilitiesRegistry.String()],
		"",
	)
	capReg, err := capabilities_registry_wrapper_v2.NewCapabilitiesRegistry(common.HexToAddress(addr), sethClient.Client)
	require.NoError(t, err, "failed to construct capabilities registry client")
	return capReg
}

// getWorkflowDONNodes returns the current on-chain node P2P IDs for the workflow DON.
func getWorkflowDONNodes(t *testing.T, testEnv *ttypes.TestEnvironment) [][32]byte {
	t.Helper()
	donInfo, err := mustWorkflowCapReg(t, testEnv).GetDONByName(&bind.CallOpts{}, "workflow-don")
	require.NoError(t, err, "failed to fetch workflow DON info")
	return donInfo.NodeP2PIds
}

// setWorkflowDONNodes updates the workflow DON's member set on-chain, preserving
// its capability configurations, F, and other settings.
func setWorkflowDONNodes(t *testing.T, testEnv *ttypes.TestEnvironment, nodes [][32]byte, testLogger zerolog.Logger) {
	t.Helper()
	require.IsType(t, &evm.Blockchain{}, testEnv.CreEnvironment.Blockchains[0], "expected EVM blockchain type")
	sethClient := testEnv.CreEnvironment.Blockchains[0].(*evm.Blockchain).SethClient
	capReg := mustWorkflowCapReg(t, testEnv)

	donName := "workflow-don"
	donInfo, err := capReg.GetDONByName(&bind.CallOpts{}, donName)
	require.NoError(t, err, "failed to fetch workflow DON info")

	updateParams := capabilities_registry_wrapper_v2.CapabilitiesRegistryUpdateDONParams{
		Name:                     donInfo.Name,
		Config:                   donInfo.Config,
		CapabilityConfigurations: donInfo.CapabilityConfigurations,
		Nodes:                    nodes,
		F:                        donInfo.F,
		IsPublic:                 donInfo.IsPublic,
	}
	tx, err := capReg.UpdateDONByName(sethClient.NewTXOpts(), donName, updateParams)
	require.NoError(t, err, "failed to update workflow DON node set")
	testLogger.Info().Str("txHash", tx.Hash().Hex()).Int("nodeCount", len(nodes)).Msg("Submitted workflow DON node-set update")
	_, err = bind.WaitMined(t.Context(), sethClient.Client, tx)
	require.NoError(t, err, "failed waiting for DON node-set update to be mined")
}

// fetchEnclaveConfig reads the config the enclave currently reports on /publicKeys.
func fetchEnclaveConfig(enclave types.Enclave) (types.EnclaveConfig, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, enclave.EnclaveURL+types.PublicKeyPath, nil)
	if err != nil {
		return types.EnclaveConfig{}, err
	}
	if err := util.SetAuthHeader(enclave, req); err != nil {
		return types.EnclaveConfig{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return types.EnclaveConfig{}, err
	}
	defer util.SafeClose(resp)
	if resp.StatusCode != http.StatusOK {
		return types.EnclaveConfig{}, fmt.Errorf("publicKeys returned status %d", resp.StatusCode)
	}
	var out types.PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return types.EnclaveConfig{}, err
	}
	return out.Config, nil
}

// fetchEnclaveSigners reads the signer set the enclave currently reports on /publicKeys.
func fetchEnclaveSigners(enclave types.Enclave) ([][]byte, error) {
	config, err := fetchEnclaveConfig(enclave)
	if err != nil {
		return nil, err
	}
	return config.Signers, nil
}

// assertEnclaveSignersConverge waits until every enclave reports exactly the expected signer set,
// proving the executor reconfigured each enclave to follow the DON membership.
func assertEnclaveSignersConverge(t *testing.T, enclaves []types.Enclave, expected [][32]byte, testLogger zerolog.Logger) {
	t.Helper()
	want := make([][]byte, len(expected))
	for i, p := range expected {
		b := make([]byte, len(p))
		copy(b, p[:])
		want[i] = b
	}
	slices.SortFunc(want, bytes.Compare)

	require.Eventually(t, func() bool {
		for _, enc := range enclaves {
			got, err := fetchEnclaveSigners(enc)
			if err != nil {
				testLogger.Info().Err(err).Str("enclave", enc.EnclaveURL).Msg("waiting for enclave signers")
				return false
			}
			gotSorted := append([][]byte{}, got...)
			slices.SortFunc(gotSorted, bytes.Compare)
			if !slices.EqualFunc(gotSorted, want, bytes.Equal) {
				testLogger.Info().Int("got", len(gotSorted)).Int("want", len(want)).Str("enclave", enc.EnclaveURL).Msg("enclave signers not yet converged")
				return false
			}
		}
		return true
	}, 3*time.Minute, 10*time.Second, "all enclaves should converge to the expected signer set")
}

func setEnclaveConfig(t *testing.T, configURL string, p2pIDs [][]byte, vaultPublicKey string, f uint32, misalign bool) {
	pubKey, err := hex.DecodeString(vaultPublicKey)
	require.NoError(t, err, "failed to decode vault public key")
	signers := p2pIDs
	if misalign {
		// Boot with the real signers plus one fake so the config does not match
		// the DON membership. The mismatch triggers the executor's boot-time reconcile,
		// which proposes removing the fake signer.
		// This exercises the full boot-then-set-config auto-update path.
		signers = make([][]byte, 0, len(p2pIDs)+1)
		signers = append(signers, p2pIDs...)
		signers = append(signers, bytes.Repeat([]byte{0xFF}, 32))
	}
	postEnclaveConfig(t, configURL, types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: pubKey,
		T:               2*f + 1,
		F:               f,
	})
}

// postEnclaveConfig POSTs the given config to the enclave's config endpoint.
func postEnclaveConfig(t *testing.T, configURL string, config types.EnclaveConfig) {
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	enclaveType := types.EnclaveTypeNitro
	if tests.UseFakeEnclave() {
		enclaveType = types.EnclaveTypeFake
	}
	_, err = util.SetNodeConfig(context.Background(), types.Enclave{
		EnclaveURL:    configURL,
		EnclaveType:   enclaveType,
		TrustedValues: [][]byte{},
		Region:        "us-west-2",
	}, types.ConfigRequest{Config: configBytes}, &client)
	require.NoError(t, err)
}

func mustStoreEnclaveSecrets(
	t *testing.T,
	gatewayURL *url.URL,
	vaultPublicKey string,
	secretIDs,
	secretValues []string,
	owner string,
	newTXOpts func() *bind.TransactOpts,
	wfRegistryContract *workflow_registry_v2_wrapper.WorkflowRegistry,
) (encryptedValues []string) {
	require.Equal(t, len(secretIDs), len(secretValues), "secretIDs and secretValues must have the same length")
	// vaultutils.EncryptSecretWithWorkflowOwner now takes a typed *tdh2easy.PublicKey
	// instead of the hex-encoded string the old crevaultfeature.EncryptSecret accepted.
	// Decode once here and reuse across all secrets.
	pkBytes, err := hex.DecodeString(vaultPublicKey)
	require.NoError(t, err, "failed to hex-decode vault public key")
	var pk tdh2easy.PublicKey
	require.NoError(t, pk.Unmarshal(pkBytes), "failed to unmarshal vault public key")
	for i := 0; i < len(secretIDs); i++ {
		ownerAddr := common.HexToAddress(owner)
		encryptedSecret, err := vaultutils.EncryptSecretWithWorkflowOwner(secretValues[i], &pk, ownerAddr)
		require.NoError(t, err, "failed to encrypt secret")
		encryptedValues = append(encryptedValues, encryptedSecret)
	}

	// VaultDON expects owner address to be in checksum format, so we convert it here
	owner = common.HexToAddress(owner).String()
	for i := range secretIDs {
		uniqueRequestID := uuid.New().String()
		secretsCreateRequest := vaultcommon.CreateSecretsRequest{
			RequestId: uniqueRequestID,
			EncryptedSecrets: []*vaultcommon.EncryptedSecret{
				{
					Id: &vaultcommon.SecretIdentifier{
						Key:       secretIDs[i],
						Owner:     owner,
						Namespace: "main",
					},
					EncryptedValue: encryptedValues[i],
				},
			},
		}
		secretsCreateRequestBody, err := json.Marshal(&secretsCreateRequest)
		require.NoError(t, err, "failed to marshal secrets request")
		secretsCreateRequestBodyJSON := json.RawMessage(secretsCreateRequestBody)
		jsonRequest := jsonrpc.Request[json.RawMessage]{
			Version: jsonrpc.JsonRpcVersion,
			ID:      uniqueRequestID,
			Method:  vaulttypes.MethodSecretsCreate,
			Params:  &secretsCreateRequestBodyJSON,
		}
		allowlistRequest(t, owner, jsonRequest, newTXOpts(), wfRegistryContract)

		requestBody, err := json.Marshal(jsonRequest)
		require.NoError(t, err, "failed to marshal secrets request")

		statusCode, httpResponseBody := sendVaultRequestToGateway(t, gatewayURL.String(), requestBody)
		require.Equal(t, http.StatusOK, statusCode, "Gateway endpoint should respond with 200 OK")

		framework.L.Info().Msg("Checking jsonResponse structure...")
		var jsonResponse jsonrpc.Response[vaulttypes.SignedOCRResponse]
		err = json.Unmarshal(httpResponseBody, &jsonResponse)
		require.NoError(t, err, "failed to unmarshal getResponse")
		framework.L.Info().Msgf("JSON Body: %v", jsonResponse)
		if jsonResponse.Error != nil {
			require.Empty(t, jsonResponse.Error.Error())
		}
		require.Equal(t, jsonrpc.JsonRpcVersion, jsonResponse.Version)
		require.Equal(t, uniqueRequestID, jsonResponse.ID)
		require.Equal(t, vaulttypes.MethodSecretsCreate, jsonResponse.Method)

		signedOCRResponse := jsonResponse.Result
		framework.L.Info().Msgf("Signed OCR Response: %s", signedOCRResponse.String())

		createSecretsResponse := vaultcommon.CreateSecretsResponse{}
		err = protojson.Unmarshal(signedOCRResponse.Payload, &createSecretsResponse)
		require.NoError(t, err, "failed to decode payload into CreateSecretsResponse proto")
		framework.L.Info().Msgf("CreateSecretsResponse decoded as: %s", createSecretsResponse.String())

		require.Len(t, createSecretsResponse.Responses, 1, "Expected one item in the response")
		for _, response := range createSecretsResponse.GetResponses() {
			require.Empty(t, response.GetError())
			require.Equal(t, secretIDs[i], response.GetId().Key)
			require.Equal(t, owner, response.GetId().Owner)
			require.Equal(t, vaulttypes.DefaultNamespace, response.GetId().Namespace)
		}
	}

	framework.L.Info().Msg("Secrets created successfully")

	return encryptedValues
}

func sendVaultRequestToGateway(t *testing.T, gatewayURL string, requestBody []byte) (statusCode int, body []byte) {
	const maxRetries = 7
	const retryInterval = 2 * time.Second

	framework.L.Info().Msgf("Request Body: %s", string(requestBody))

	for attempt := range maxRetries + 1 {
		req, err := http.NewRequestWithContext(t.Context(), "POST", gatewayURL, bytes.NewBuffer(requestBody))
		require.NoError(t, err, "failed to create request")

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err, "failed to execute request")

		body, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, "failed to read http response body")
		statusCode = resp.StatusCode

		framework.L.Info().Msgf("HTTP Response Body: %s", string(body))

		if !isGatewayNotAllowlistedError(body) {
			return statusCode, body
		}

		if attempt < maxRetries {
			framework.L.Warn().Msgf("Request not yet allowlisted, retrying in %s (attempt %d/%d)...", retryInterval, attempt+1, maxRetries)
			time.Sleep(retryInterval)
		}
	}

	return statusCode, body
}

// isGatewayNotAllowlistedError checks whether the response is a gateway-level
// "request not allowlisted" rejection (method is empty, error code -32600).
// Node-level rejections (method is set, code -32603) have a different format
// and must not be retried because the gateway has already consumed the request.
func isGatewayNotAllowlistedError(body []byte) bool {
	var resp struct {
		Method string `json:"method"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return false
	}
	return resp.Method == "" && resp.Error != nil &&
		strings.Contains(resp.Error.Message, "request not allowlisted")
}

// getHostIP returns the host's IP address accessible from Docker containers
func getHostIP() string {
	// First try to use host.docker.internal if available
	if _, err := net.LookupHost("host.docker.internal"); err == nil {
		return "host.docker.internal"
	}

	// Fallback: get the default route interface IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// Final fallback to localhost (for local testing)
		return "localhost"
	}
	defer util.SafeClose(&http.Response{Body: conn})

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func allowlistRequest(t *testing.T, owner string, request jsonrpc.Request[json.RawMessage], opts *bind.TransactOpts, wfRegistryContract *workflow_registry_v2_wrapper.WorkflowRegistry) {
	digestHex, err := request.Digest()
	require.NoError(t, err, "failed to get digest for request")
	requestDigestBytes, err := hex.DecodeString(digestHex)
	require.NoError(t, err, "failed to decode digest")
	reqDigestBytes32 := [32]byte(requestDigestBytes)

	require.NoError(t, err, "failed to get digest for request")
	_, err = wfRegistryContract.AllowlistRequest(opts, reqDigestBytes32, uint32(time.Now().Add(1*time.Hour).Unix())) //nolint:gosec // disable G115
	require.NoError(t, err, "failed to allowlist request")

	framework.L.Info().Msgf("Allowlisting request digest at contract %s, for owner: %s, digestHexStr: %s", wfRegistryContract.Address().Hex(), owner, digestHex)
	allowedList, err := wfRegistryContract.GetAllowlistedRequests(&bind.CallOpts{}, big.NewInt(0), big.NewInt(100))
	require.NoError(t, err, "failed to validate allowlisted request")
	for _, req := range allowedList {
		if req.RequestDigest == reqDigestBytes32 {
			framework.L.Info().Msgf("Request digest found in allowlist")
		}
		framework.L.Info().Msgf("Allowlisted request digestHexStr: %s, owner: %s, expiry: %d", hex.EncodeToString(req.RequestDigest[:]), req.Owner.Hex(), req.ExpiryTimestamp)
	}
}

func startProxy(t *testing.T, target string, logger zerolog.Logger) (string, func()) {
	targetURL, err := url.Parse(target)
	require.NoError(t, err)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	const sessionHeader = types.StickySessionHeader
	sessionID := uuid.New().String()

	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.URL.Path == "/publicKeys" {
			resp.Header.Set(sessionHeader, sessionID)
			logger.Info().Str("sessionID", sessionID).Msg("Proxy: injected session header")
		}
		return nil
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("x-api-key")
		if apiKey != "foobar" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			logger.Info().Msgf("Proxy: received x-api-key: %s", apiKey)
		}

		if r.Method == http.MethodPost && r.URL.Path == "/requests" {
			if got := r.Header.Get(sessionHeader); got != sessionID {
				logger.Error().Str("expected", sessionID).Str("got", got).Msg("Proxy: invalid or missing session header")
			} else {
				logger.Info().Msg("Proxy: validated session persistence header")
			}
		}

		proxy.ServeHTTP(w, r)
	})

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)

	server := &http.Server{Handler: handler}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("Proxy server failed")
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	hostIP := getHostIP()
	return fmt.Sprintf("http://%s:%d", hostIP, port), func() {
		err := server.Close()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to close proxy server")
		}
	}
}
