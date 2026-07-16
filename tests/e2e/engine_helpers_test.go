package tests

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/confidential-compute/tests"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
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

// startNitroEnclaves brings up two local Nitro enclaves for an app and returns
// the resulting enclave descriptors, config URLs, and a combined cleanup. The
// first enclave is wrapped in a local API-key-injecting proxy.
func startNitroEnclaves(t *testing.T, app App, logger zerolog.Logger) ([]types.Enclave, []string, func()) {
	t.Helper()
	var enclaves []types.Enclave
	var configURLs []string
	var cleanups []func()

	logger.Info().Msgf("Starting local Nitro enclave for app: %s", app.Name)
	rootDir, err := util.GetRepoRoot()
	require.NoError(t, err)
	baseCID := 16
	httpPorts := allocateNitroTestPorts(t, 2)
	configHttpPorts := allocateNitroTestPorts(t, 2)
	logger.Info().Msgf(
		"Allocated Nitro test ports for %s: host=%v config=%v",
		app.Name,
		httpPorts,
		configHttpPorts,
	)

	logger.Info().Msgf("Cleaning up stale processes on ports...")
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
		cleanups = append(cleanups, cleanup)

		measurements, err := tests.EnsureEnclaveAndGetMeasurements(baseCID + i)
		require.NoError(t, err, "Failed to get enclave measurements")

		hostIP := getHostIP()
		logger.Info().Msgf("Using host IP: %s for enclave communication", hostIP)

		enclaveURL := fmt.Sprintf("http://%s:%s", hostIP, httpPorts[i])
		if i == 0 {
			proxyURL, proxyCleanup := startProxy(t, enclaveURL, logger)
			cleanups = append(cleanups, proxyCleanup)
			logger.Info().Msgf("Started proxy for enclave 0 at %s forwarding to %s", proxyURL, enclaveURL)
			enclaveURL = proxyURL
		}

		enclaveType := types.EnclaveTypeNitro
		if tests.UseFakeEnclave() {
			enclaveType = types.EnclaveTypeFake
		}
		enclaves = append(enclaves, types.Enclave{
			EnclaveType:      enclaveType,
			EnclaveExtraData: []byte{},
			EnclaveID:        [32]byte{uint8(i + 1)},
			TrustedValues:    [][]byte{[]byte("invalid"), measurements},
			EnclaveURL:       enclaveURL,
		})
		configURLs = append(configURLs, fmt.Sprintf("http://localhost:%s", configHttpPorts[i]))
	}

	return enclaves, configURLs, func() {
		for _, fn := range cleanups {
			fn()
		}
	}
}
