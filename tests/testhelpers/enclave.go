// Package testhelpers provides reusable helpers for launching and managing
// AWS Nitro Enclaves in integration and E2E tests. It is designed to be
// imported from any repository with minimal transitive dependencies.
package testhelpers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
)

// enclaveReadyTimeout bounds how long SetupLocalEnclaves waits for the host
// server to report readiness. Startup includes a Docker image build of the
// enclave Dockerfile (CGO/wasmtime for confidential-workflows, go mod download
// for all apps), which on a cold runner cache can run well past 15 minutes
// after a chainlink-common dep bump pulls in many transitive packages.
const enclaveReadyTimeout = 60 * time.Minute

// Must exceed the host's 25-second shutdown timeout.
const hostServerExitBudget = 35 * time.Second

// ---------------------------------------------------------------------------
// High-level setup API
// ---------------------------------------------------------------------------

// LocalEnclaveSetupConfig holds configuration for provisioning one or more
// local enclaves on the current host. All path fields accept absolute paths,
// making this safe to use from any repository that has checked out the
// chainlink-confidential-compute repo at an arbitrary location.
type LocalEnclaveSetupConfig struct {
	// RepoRoot is the absolute path to the root of the
	// chainlink-confidential-compute repository checkout. The build script and
	// Dockerfiles are resolved relative to this path.
	RepoRoot string

	// AppName is the name of the enclave application to launch (e.g.
	// "confidential-http", "confidential-workflows").
	AppName string

	// EnclaveCount is the number of enclaves to start (default 2).
	// Ignored if HTTPPorts is set.
	EnclaveCount int

	// BaseCID is the starting vsock CID for the first enclave. Subsequent
	// enclaves increment from this value.
	BaseCID int

	// BaseHTTPPort is the starting HTTP port for the first enclave's host
	// server. Subsequent enclaves increment by 1.
	// Ignored if HTTPPorts is set.
	BaseHTTPPort int

	// BaseConfigHTTPPort is the starting config HTTP port for the first
	// enclave's host server. Subsequent enclaves increment by 1.
	// Ignored if ConfigHTTPPorts is set.
	BaseConfigHTTPPort int

	// HTTPPorts optionally specifies exact HTTP ports for each enclave.
	// When set, BaseHTTPPort is ignored and len(HTTPPorts) determines
	// EnclaveCount.
	HTTPPorts []string

	// ConfigHTTPPorts optionally specifies exact config HTTP ports for each
	// enclave. When set, BaseConfigHTTPPort is ignored.
	ConfigHTTPPorts []string

	// HostIP is the IP address that Docker containers can reach the host at.
	// If empty, it is auto-detected via DetectHostIP.
	HostIP string

	// BinaryPath optionally overrides the capability binary that the enclave
	// builds into its Docker image. When set, the file at this path is copied
	// into the expected build location before the enclave build script runs.
	BinaryPath string

	// EnclaveType is the enclave type recorded on each returned descriptor.
	// If empty, it is derived from UseFakeEnclave.
	EnclaveType types.EnclaveType

	// Region is the AWS region recorded on each returned descriptor. Enclave
	// descriptor hashes cover this field, so it must match what the enclave
	// itself reports. Empty leaves it unset.
	Region string

	// ExtraEnv holds additional "KEY=VALUE" environment entries passed to the
	// enclave build-and-run script, appended after the defaults so they can
	// override them.
	ExtraEnv []string
}

// LocalEnclaveResult holds the output of SetupLocalEnclaves: the enclaves,
// config URLs, and cleanup functions to tear everything down.
type LocalEnclaveResult struct {
	// Enclaves is the slice of enclave descriptors suitable for passing to the
	// enclave client pool or capability job constructor.
	Enclaves []types.Enclave

	// ConfigURLs is the list of config-plane URLs (one per enclave), used to
	// push EnclaveConfig (signers, master public key, etc.).
	ConfigURLs []string

	// HTTPPorts is the list of HTTP ports (one per enclave) the host server
	// listens on. Useful for setting up proxies or allowlists.
	HTTPPorts []string

	// ConfigHTTPPorts is the list of config HTTP ports (one per enclave).
	ConfigHTTPPorts []string

	// HostIP is the detected (or configured) host IP used in enclave URLs.
	HostIP string

	// Cleanups is a slice of cleanup functions (one per enclave) that
	// terminate the enclave and its host server. Call them in order or use
	// CleanupAll.
	Cleanups []func()
}

// CleanupAll runs every registered cleanup function in order.
func (r *LocalEnclaveResult) CleanupAll() {
	for _, fn := range r.Cleanups {
		fn()
	}
}

// DefaultLocalEnclaveSetupConfig returns a config with sensible defaults for
// two enclaves starting at CID 16, HTTP port 8080, config port 8082.
func DefaultLocalEnclaveSetupConfig(repoRoot, appName string) LocalEnclaveSetupConfig {
	return LocalEnclaveSetupConfig{
		RepoRoot:           repoRoot,
		AppName:            appName,
		EnclaveCount:       2,
		BaseCID:            16,
		BaseHTTPPort:       8080,
		BaseConfigHTTPPort: 8082,
	}
}

// SetupLocalEnclaves provisions one or more local enclaves on the current host.
// It:
//  1. Kills any stale processes on the target ports.
//  2. Starts each enclave via the app's build-and-run script.
//  3. Retrieves PCR measurements from each running enclave.
//  4. Returns Enclave descriptors with TrustedValues pre-populated.
//
// This function is designed to be called from any repository that has a
// checkout of chainlink-confidential-compute available at config.RepoRoot.
//
// Prerequisites on the runner:
//   - For real enclaves: nitro-cli installed and the allocator configured (use
//     the setup-nitro-enclave GitHub Action).
//   - The capability binary must be built and placed at the expected location,
//     OR config.BinaryPath must point to a pre-built binary.
func SetupLocalEnclaves(t *testing.T, config LocalEnclaveSetupConfig) *LocalEnclaveResult {
	t.Helper()

	if config.EnclaveCount == 0 {
		config.EnclaveCount = 2
	}
	if config.BaseCID == 0 {
		config.BaseCID = 16
	}
	if config.BaseHTTPPort == 0 {
		config.BaseHTTPPort = 8080
	}
	if config.BaseConfigHTTPPort == 0 {
		config.BaseConfigHTTPPort = 8082
	}
	if config.HostIP == "" {
		config.HostIP = DetectHostIP()
	}
	if config.EnclaveType == "" {
		config.EnclaveType = types.EnclaveTypeNitro
		if UseFakeEnclave() {
			config.EnclaveType = types.EnclaveTypeFake
		}
	}

	// If a custom binary path was provided, copy it to the expected location.
	if config.BinaryPath != "" {
		destPath := filepath.Join(config.RepoRoot, "tests", "e2e", "binaries", config.AppName)
		copyCmd := exec.Command("cp", config.BinaryPath, destPath)
		output, err := copyCmd.CombinedOutput()
		require.NoError(t, err, "failed to copy binary to expected location: %s", string(output))
	}

	// Build port slices — use explicit ports if provided, otherwise generate
	// sequential ports from Base* values.
	var httpPorts, configPorts []string
	if len(config.HTTPPorts) > 0 {
		httpPorts = config.HTTPPorts
		config.EnclaveCount = len(httpPorts)
	} else {
		httpPorts = make([]string, config.EnclaveCount)
		for i := range config.EnclaveCount {
			httpPorts[i] = strconv.Itoa(config.BaseHTTPPort + i)
		}
	}
	if len(config.ConfigHTTPPorts) > 0 {
		configPorts = config.ConfigHTTPPorts
	} else {
		configPorts = make([]string, config.EnclaveCount)
		for i := range config.EnclaveCount {
			configPorts[i] = strconv.Itoa(config.BaseConfigHTTPPort + i)
		}
	}
	require.Len(t, configPorts, len(httpPorts), "HTTPPorts and ConfigHTTPPorts must have the same length")

	// Kill stale processes.
	for i := range httpPorts {
		KillProcessOnPort(t, httpPorts[i])
		KillProcessOnPort(t, configPorts[i])
	}

	result := &LocalEnclaveResult{
		HostIP:          config.HostIP,
		HTTPPorts:       httpPorts,
		ConfigHTTPPorts: configPorts,
	}

	// Start each enclave.
	for i := range httpPorts {
		enclaveCID := strconv.Itoa(config.BaseCID + i)
		enclaveName := fmt.Sprintf("go-enclave-%s-%d", config.AppName, i)
		isFirstEnclave := i == 0

		cleanup := MustSetupEnclaveWithEnv(
			t, config.RepoRoot, enclaveCID,
			httpPorts[i], configPorts[i],
			config.AppName, enclaveName, isFirstEnclave,
			config.ExtraEnv,
		)
		result.Cleanups = append(result.Cleanups, cleanup)

		measurements, err := EnsureEnclaveAndGetMeasurements(config.BaseCID + i)
		require.NoError(t, err, "failed to get enclave measurements for CID %s", enclaveCID)

		result.Enclaves = append(result.Enclaves, types.Enclave{
			EnclaveType:      config.EnclaveType,
			EnclaveExtraData: []byte{},
			EnclaveID:        [32]byte{uint8(i + 1)},
			// Two trusted values ensure callers can handle more than one.
			TrustedValues: [][]byte{[]byte("invalid"), measurements},
			EnclaveURL:    fmt.Sprintf("http://%s:%s", config.HostIP, httpPorts[i]),
			Region:        config.Region,
		})
		result.ConfigURLs = append(result.ConfigURLs, fmt.Sprintf("http://localhost:%s", configPorts[i]))
	}

	return result
}

// RemoteEnclaveSetupConfig describes a set of already-deployed enclaves.
type RemoteEnclaveSetupConfig struct {
	// URLsCSV is a comma-separated list of enclave data-plane URLs.
	URLsCSV string

	// ConfigURLsCSV is a comma-separated list of config-plane URLs. When
	// empty, URLsCSV is used for both planes.
	ConfigURLsCSV string

	// PCRMeasurementsJSON is the contents of a pcr_measurements.json file, in
	// the format produced by `nitro-cli describe-eif`.
	PCRMeasurementsJSON []byte

	// EnclaveType is the enclave type recorded on each returned descriptor.
	// If empty, it is derived from UseFakeEnclave.
	EnclaveType types.EnclaveType

	// Region is the AWS region recorded on each returned descriptor.
	Region string
}

// ParseRemoteEnclaves parses enclave URLs and a PCR measurements JSON document
// into Enclave descriptors and config URLs. This is the counterpart to
// SetupLocalEnclaves for pre-deployed enclaves.
func ParseRemoteEnclaves(config RemoteEnclaveSetupConfig) (enclaves []types.Enclave, configURLs []string, err error) {
	var pcrMeasurements nitro.Measurements
	if err := json.Unmarshal(config.PCRMeasurementsJSON, &pcrMeasurements); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal PCR measurements: %w", err)
	}
	mBytes, err := json.Marshal(pcrMeasurements.Measurements)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-marshal PCR measurements: %w", err)
	}

	if config.EnclaveType == "" {
		config.EnclaveType = types.EnclaveTypeNitro
		if UseFakeEnclave() {
			config.EnclaveType = types.EnclaveTypeFake
		}
	}

	urls := strings.Split(config.URLsCSV, ",")
	cfgURLs := urls
	if config.ConfigURLsCSV != "" {
		cfgURLs = strings.Split(config.ConfigURLsCSV, ",")
		if len(cfgURLs) != len(urls) {
			return nil, nil, fmt.Errorf("enclave URLs (%d) and config URLs (%d) must have the same number of entries", len(urls), len(cfgURLs))
		}
	}

	for i, u := range urls {
		enclaves = append(enclaves, types.Enclave{
			EnclaveType:      config.EnclaveType,
			EnclaveExtraData: []byte{},
			EnclaveID:        [32]byte{uint8(i + 1)},
			TrustedValues:    [][]byte{mBytes},
			EnclaveURL:       strings.TrimSpace(u),
			Region:           config.Region,
		})
		configURLs = append(configURLs, strings.TrimSpace(cfgURLs[i]))
	}
	return enclaves, configURLs, nil
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

// UseFakeEnclave reports whether the test harness should provision fake enclaves
// instead of real Nitro enclaves. An explicit ENCLAVE_TYPE=FAKE always selects
// fake. Otherwise, when ENCLAVE_TYPE is unset and nitro-cli is not installed,
// the harness falls back to fake so tests run on non-Nitro machines without the
// caller needing to set anything — except when REMOTE_ENCLAVE_URLS points the
// run at remote real enclaves.
func UseFakeEnclave() bool {
	if os.Getenv(types.EnvEnclaveType) == string(types.EnclaveTypeFake) {
		return true
	}
	if os.Getenv("REMOTE_ENCLAVE_URLS") != "" {
		return false
	}
	if _, pinned := os.LookupEnv(types.EnvEnclaveType); !pinned {
		if _, err := exec.LookPath("nitro-cli"); err != nil {
			return true
		}
	}
	return false
}

// Match the CID so sibling enclave processes are not mistaken for leaks.
func hostServerPIDs(t *testing.T, rootDir, app, enclaveCID string) ([]string, bool) {
	pattern := regexp.QuoteMeta(filepath.Join(rootDir, "enclave", "apps", app, "host-server")) +
		`.*--enclave-cid=` + regexp.QuoteMeta(enclaveCID) + `([[:space:]]|$)`
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		return nil, true
	default:
		t.Errorf("cannot verify the host server exited: pgrep %q: %v", pattern, err)
		return nil, false
	}
	return strings.Fields(string(out)), true
}

// A leaked host server retains parent-wide VSOCK port 5001 after HTTP shutdown.
func requireHostServerStopped(t *testing.T, rootDir, app, enclaveCID string) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Logf("pgrep unavailable; cannot verify the host server exited")
		return
	}
	deadline := time.Now().Add(hostServerExitBudget)
	for {
		pids, ok := hostServerPIDs(t, rootDir, app, enclaveCID)
		if !ok || len(pids) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("a host server for CID %s survived cleanup after %s; it still holds VSOCK 5001 and would stop the next suite's broker starting (pids %s)",
				enclaveCID, hostServerExitBudget, strings.Join(pids, " "))
			for _, pid := range pids {
				_ = exec.Command("kill", "-9", pid).Run()
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// KillProcessOnPort kills any process listening on the specified port. The
// LISTEN filter avoids killing clients whose remote endpoint uses that port.
func KillProcessOnPort(t *testing.T, port string) {
	t.Helper()

	cmd := exec.Command("lsof", "-ti:"+port, "-sTCP:LISTEN")
	output, err := cmd.Output()
	if err != nil {
		// No process found on this port, which is fine
		return
	}

	pids := strings.TrimSpace(string(output))
	if pids == "" {
		return
	}

	for _, pid := range strings.Split(pids, "\n") {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}

		t.Logf("Killing process %s on port %s", pid, port)
		killCmd := exec.Command("kill", "-TERM", pid)
		_ = killCmd.Run() // Ignore error, process might already be dead

		// Wait a bit for graceful shutdown
		time.Sleep(500 * time.Millisecond)

		// Check if still running
		checkCmd := exec.Command("kill", "-0", pid)
		if checkCmd.Run() == nil {
			// Process still running, force kill
			t.Logf("Force killing process %s on port %s", pid, port)
			forceKillCmd := exec.Command("kill", "-9", pid)
			_ = forceKillCmd.Run()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// MustSetupEnclave starts a single enclave using the build-and-run script for
// the selected enclave environment (real Nitro or fake). It blocks until the
// host server reports readiness and returns a cleanup function that terminates
// the enclave.
func MustSetupEnclave(t *testing.T, rootDir string, enclaveCID string, httpPort string, configHttpPort string, app string, enclaveName string, isFirstEnclave bool) func() {
	t.Helper()
	return MustSetupEnclaveWithEnv(t, rootDir, enclaveCID, httpPort, configHttpPort, app, enclaveName, isFirstEnclave, nil)
}

// MustSetupEnclaveWithEnv is MustSetupEnclave with additional "KEY=VALUE"
// environment entries appended after the defaults, allowing callers to override
// them.
func MustSetupEnclaveWithEnv(t *testing.T, rootDir string, enclaveCID string, httpPort string, configHttpPort string, app string, enclaveName string, isFirstEnclave bool, extraEnv []string) func() {
	t.Helper()

	scriptName := "build-and-run-go-enclave.sh"
	scriptDir := "nitro"
	if UseFakeEnclave() {
		scriptName = "build-and-run-fake-enclave.sh"
		scriptDir = "fake"
	}
	buildAndRunPath := filepath.Join(rootDir, "enclave", scriptDir, scriptName)
	if _, err := os.Stat(buildAndRunPath); os.IsNotExist(err) {
		t.Fatalf("%s script not found at: %s", scriptName, buildAndRunPath)
	}

	// Rebuild once, then reuse the shared EIF for subsequent enclaves.
	staleEIF := filepath.Join(rootDir, "enclave", "apps", app, "go-enclave-outbound.eif")
	if isFirstEnclave {
		if err := os.Remove(staleEIF); err == nil {
			t.Logf("Removed stale EIF: %s", staleEIF)
		}
	}

	// Kill any existing processes on the target ports before starting
	t.Logf("Checking for existing processes on ports %s and %s...", httpPort, configHttpPort)
	KillProcessOnPort(t, httpPort)
	KillProcessOnPort(t, configHttpPort)

	// Set up a cleanup handler to kill the enclave process.
	var enclaveCmd *exec.Cmd
	cleanup := func() {
		// First, kill the enclave process
		if enclaveCmd != nil && enclaveCmd.Process != nil {
			t.Log("Terminating enclave process...")
			_ = enclaveCmd.Process.Signal(os.Interrupt) // Try graceful shutdown first

			// Wait a bit for graceful shutdown
			time.Sleep(500 * time.Millisecond)

			// Then force kill if needed
			_ = enclaveCmd.Process.Kill()

			// Wait for process to exit, but don't treat expected signals as errors
			if err := enclaveCmd.Wait(); err != nil {
				// These errors are expected when we kill the process
				errStr := err.Error()
				if errStr != "signal: killed" && errStr != "signal: terminated" &&
					errStr != "signal: interrupt" && errStr != "context canceled" {
					t.Logf("Unexpected error waiting for enclave process: %v", err)
				}
			}
		}

		// Terminate the specific enclave by name (only if using real nitro environment)
		if !UseFakeEnclave() {
			t.Logf("Terminating enclave '%s' via nitro-cli...", enclaveName)
			cleanupCmd := exec.Command("nitro-cli", "terminate-enclave", "--enclave-name", enclaveName)
			cleanupOutput, err := cleanupCmd.CombinedOutput()
			if err != nil {
				t.Logf("Failed to terminate enclave '%s': %v, output: %s", enclaveName, err, string(cleanupOutput))
			} else {
				t.Logf("Enclave '%s' terminated successfully", enclaveName)
			}
		}

		// Give the bash script and host-server time to clean up
		// The script should handle killing the host-server when it exits
		time.Sleep(1 * time.Second)

		// Verify broker shutdown after the HTTP listener closes.
		requireHostServerStopped(t, rootDir, app, enclaveCID)
		KillProcessOnPort(t, httpPort)
		KillProcessOnPort(t, configHttpPort)
	}

	t.Logf("Starting enclave '%s' with CID %s on ports %s/%s...", enclaveName, enclaveCID, httpPort, configHttpPort)
	startupResult := make(chan error, 1)
	// The returned cleanup, not this function's context, owns the script.
	enclaveCmd = exec.Command(buildAndRunPath) //nolint:gosec // fixed in-repo script path
	enclaveCmd.Dir = rootDir

	// Build environment variables
	envVars := []string{
		fmt.Sprintf("%s=%s", types.EnvEnclaveCID, enclaveCID),
		fmt.Sprintf("HTTP_PORT=%s", httpPort),
		fmt.Sprintf("CONFIG_HTTP_PORT=%s", configHttpPort),
		fmt.Sprintf("APP=%s", app),
		fmt.Sprintf("ENCLAVE_NAME=%s", enclaveName),
		"KEYPAIR_ROTATION=15s",
		"KEYPAIR_EXPIRATION=10m",
		// Let tests re-POST /config to exercise reconfiguration (e.g. zeroing an
		// enclave's config and restoring it).
		"ALLOW_RECONFIG=true",
	}

	// For subsequent enclaves, skip allocator restart and image rebuilding
	if !isFirstEnclave {
		envVars = append(envVars, "SKIP_ALLOCATOR_RESTART=true", "SKIP_IMAGE_BUILD=true")
	}

	envVars = append(envVars, extraEnv...)

	enclaveCmd.Env = append(os.Environ(), envVars...)
	enclaveOut, err := enclaveCmd.StdoutPipe()
	require.NoError(t, err)
	enclaveErr, err := enclaveCmd.StderrPipe()
	require.NoError(t, err)
	err = enclaveCmd.Start()
	require.NoError(t, err, "Failed to start enclave process")

	// Register before readiness checks because Fatal calls Goexit.
	var cleanupOnce sync.Once
	runCleanup := func() { cleanupOnce.Do(cleanup) }
	t.Cleanup(runCleanup)

	// Monitor enclave stdout for readiness.
	go func() {
		scanner := bufio.NewScanner(enclaveOut)
		ready := false
		for scanner.Scan() {
			line := scanner.Text()

			if !ready && strings.Contains(line, "API endpoints available at") {
				ready = true
				startupResult <- nil
			}

			t.Logf("[Enclave setup]: %s", line)
		}
		if !ready {
			if err := scanner.Err(); err != nil {
				startupResult <- fmt.Errorf("reading enclave startup output: %w", err)
				return
			}
			startupResult <- errors.New("enclave startup exited before readiness")
		}
	}()

	// Monitor enclave errors (docker build writes progress/errors here).
	go func() {
		scanner := bufio.NewScanner(enclaveErr)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("[Enclave setup stderr]: %s", line)
		}
	}()

	t.Log("Waiting for enclave to be ready...")
	select {
	case err := <-startupResult:
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Enclave is ready!")
	case <-time.After(enclaveReadyTimeout):
		t.Fatal("Timeout waiting for enclave to start")
	}
	time.Sleep(10 * time.Second)

	return runCleanup
}

// enclaveDescribeEntry represents the JSON output of `nitro-cli describe-enclaves`.
type enclaveDescribeEntry struct {
	EnclaveCID   int        `json:"EnclaveCID"`
	Measurements nitro.PCRs `json:"Measurements"`
}

// EnsureEnclaveAndGetMeasurements retrieves PCR measurements for a running
// enclave identified by its CID. Fake enclaves report placeholder measurements.
func EnsureEnclaveAndGetMeasurements(enclaveCID int) ([]byte, error) {
	if UseFakeEnclave() {
		return []byte(types.FakeMeasurements), nil
	}

	cmd := exec.Command("nitro-cli", "describe-enclaves")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run nitro-cli describe-enclaves: %w", err)
	}

	var entries []enclaveDescribeEntry
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse nitro-cli output: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no running enclaves found")
	}

	for _, entry := range entries {
		if entry.EnclaveCID == enclaveCID {
			measurementsBytes, err := json.Marshal(entry.Measurements)
			if err != nil {
				return nil, err
			}
			return measurementsBytes, nil
		}
	}

	var availableCIDs []int
	for _, entry := range entries {
		availableCIDs = append(availableCIDs, entry.EnclaveCID)
	}
	return nil, fmt.Errorf("enclave with CID %d not found, available CIDs: %v", enclaveCID, availableCIDs)
}

// DetectHostIP returns the host's IP address accessible from Docker containers.
func DetectHostIP() string {
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
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Failed to close UDP connection: %v\n", err)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
