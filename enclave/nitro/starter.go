package nitro

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"

	"log"

	"github.com/hf/nsm"
	outboundhttps "github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outbound-https"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// OpenNitroAttestor opens an NSM session and returns a Nitro attestor along
// with a cleanup function that closes the session. Call the cleanup function
// (typically via defer) when the attestor is no longer needed.
func OpenNitroAttestor() (attestor.Attestor, func(), error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open NSM session: %v", err)
	}
	cleanup := func() {
		if err := session.Close(); err != nil {
			log.Printf("Failed to close NSM session: %v", err)
		}
	}
	return attestor.NewNitroAttestor(session), cleanup, nil
}

func StartNitroEnclave(
	app types.EnclaveApp,
	att attestor.Attestor,
	keychain keychain.Keychain,
	combiner combiner.Combiner,
	logger *log.Logger,
	emitter types.Emitter,
	vsockPort *uint,
	allowReconfig bool,
) error {
	if *vsockPort > math.MaxUint32 {
		logger.Fatalf("Invalid port")
	}

	// Set up outbound HTTPS connectivity.
	ok := outboundhttps.SetupConnectivity()
	if !ok {
		return fmt.Errorf("failed to set up outbound HTTPS connectivity")
	}

	// Verify PTP clock synchronization.
	clockSource := getClockSource()
	if clockSource != "kvm-clock" {
		return fmt.Errorf("invalid clock source: %s", clockSource)
	}
	chronySources := getChronySources()
	if strings.Contains(chronySources, "* PHC") {
	} else {
		return fmt.Errorf("invalid PTP time synchronization source: %s", chronySources)
	}

	// Instantiate a new enclave server.
	verifier := signatureverifier.NewEd25519SignatureVerifier()
	server := server.NewEnclaveServer(
		app,
		att,
		logger,
		keychain,
		verifier,
		combiner,
		emitter,
		types.EnclaveConfig{},
		allowReconfig,
	)

	// Start the server.
	var listener net.Listener
	listener, err := vsock.Listen(uint32(*vsockPort), nil)
	if err != nil {
		logger.Fatalf("cannot listen on vsock: %v", err)
	}
	defer listener.Close() //nolint:errcheck // best-effort cleanup
	return server.Start(listener)
}

func getClockSource() string {
	data, err := os.ReadFile("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	if err != nil {
		return fmt.Sprintf("error reading clock source: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func getChronySources() string {
	cmd := exec.Command("chronyc", "sources")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error getting chrony sources: %v", err)
	}
	return string(output)
}
