package tests

import (
	"net"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

// allocateNitroTestPorts binds count ephemeral TCP ports on localhost, captures
// their numbers, then releases them before returning. Used to reserve ports for
// Nitro enclaves without actually listening.
func allocateNitroTestPorts(t *testing.T, count int) []string {
	t.Helper()

	listeners := make([]net.Listener, 0, count)
	ports := make([]string, 0, count)

	for range count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "failed to allocate free TCP port")

		listeners = append(listeners, ln)
		ports = append(ports, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}

	for _, ln := range listeners {
		require.NoError(t, ln.Close(), "failed to release reserved TCP port")
	}

	return ports
}

// startNitroEnclaves brings up local Nitro enclaves for an app and returns
// the resulting enclave descriptors, config URLs, and a combined cleanup. The
// first enclave is wrapped in a local API-key-injecting proxy.
func startNitroEnclaves(t *testing.T, app App, logger zerolog.Logger) ([]types.Enclave, []string, func()) {
	t.Helper()

	logger.Info().Msgf("Starting local Nitro enclave for app: %s", app.Name)
	rootDir, err := util.GetRepoRoot()
	require.NoError(t, err)

	// VSOCK port 5001 permits one host process per Nitro parent.
	enclaveCount := 2
	if !testhelpers.UseFakeEnclave() {
		enclaveCount = 1
	}
	httpPorts := allocateNitroTestPorts(t, enclaveCount)
	configHttpPorts := allocateNitroTestPorts(t, enclaveCount)
	logger.Info().Msgf(
		"Allocated Nitro test ports for %s: host=%v config=%v",
		app.Name,
		httpPorts,
		configHttpPorts,
	)

	cfg := testhelpers.LocalEnclaveSetupConfig{
		RepoRoot:        rootDir,
		AppName:         app.Name,
		HTTPPorts:       httpPorts,
		ConfigHTTPPorts: configHttpPorts,
	}
	result := testhelpers.SetupLocalEnclaves(t, cfg)
	logger.Info().Msgf("Using host IP: %s for enclave communication", result.HostIP)

	// Wrap the first enclave in an API-key-injecting proxy.
	if len(result.Enclaves) > 0 {
		enclaveURL := result.Enclaves[0].EnclaveURL
		proxyURL, proxyCleanup := startProxy(t, enclaveURL, logger)
		result.Cleanups = append(result.Cleanups, proxyCleanup)
		logger.Info().Msgf("Started proxy for enclave 0 at %s forwarding to %s", proxyURL, enclaveURL)
		result.Enclaves[0].EnclaveURL = proxyURL
	}

	return result.Enclaves, result.ConfigURLs, result.CleanupAll
}
