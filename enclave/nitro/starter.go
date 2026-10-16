package nitro

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"log"

	"github.com/hf/nsm"
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

	if err := verifyEnvironment(logger, environmentChecks(), environmentCheckAttempts, environmentCheckDelay); err != nil {
		return err
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

func validateClockSource(architecture, source string) error {
	var expected string
	switch architecture {
	case "amd64":
		expected = "kvm-clock"
	case "arm64":
		expected = "arch_sys_counter"
	default:
		return fmt.Errorf("unsupported Nitro architecture: %s", architecture)
	}
	if source != expected {
		return fmt.Errorf("invalid clock source for %s: %s, want %s", architecture, source, expected)
	}
	return nil
}

// environmentCheckAttempts and environmentCheckDelay bound how long boot waits
// out transient parent-instance conditions, such as chrony not yet synced to
// the PHC, before the enclave exits.
const (
	environmentCheckAttempts = 30
	environmentCheckDelay    = 2 * time.Second
)

type environmentCheck struct {
	name  string
	check func() error
}

// environmentChecks verify that the NSM is the hardware RNG feeding the kernel
// entropy pool and that the clock is PTP-synchronized.
func environmentChecks() []environmentCheck {
	return []environmentCheck{
		{"entropy source", VerifyEntropySource},
		{"clock source", func() error { return checkClockSource(runtime.GOARCH, os.ReadFile) }},
		{"PTP time synchronization", func() error { return checkChronySources(chronySources) }},
	}
}

// verifyEnvironment runs each check in order, retrying a failing check up to
// attempts times, and fails with the last error of the first check that never
// passes.
func verifyEnvironment(logger *log.Logger, checks []environmentCheck, attempts int, delay time.Duration) error {
	for _, c := range checks {
		var err error
		for attempt := 1; attempt <= attempts; attempt++ {
			if err = c.check(); err == nil {
				break
			}
			logger.Printf("%s check failed (attempt %d/%d): %v", c.name, attempt, attempts, err)
			if attempt < attempts {
				time.Sleep(delay)
			}
		}
		if err != nil {
			return fmt.Errorf("%s check failed after %d attempts: %w", c.name, attempts, err)
		}
	}
	return nil
}

func checkClockSource(architecture string, readFile func(string) ([]byte, error)) error {
	data, err := readFile("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	if err != nil {
		return fmt.Errorf("reading clock source: %w", err)
	}
	return validateClockSource(architecture, strings.TrimSpace(string(data)))
}

func checkChronySources(sources func() ([]byte, error)) error {
	output, err := sources()
	if err != nil {
		return fmt.Errorf("running chronyc sources: %w", err)
	}
	if !strings.Contains(string(output), "* PHC") {
		return fmt.Errorf("invalid PTP time synchronization source: %s", output)
	}
	return nil
}

func chronySources() ([]byte, error) {
	return exec.Command("chronyc", "sources").CombinedOutput()
}
