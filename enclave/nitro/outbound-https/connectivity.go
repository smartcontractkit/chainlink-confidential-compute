package outboundhttps

import (
	"os"
	"os/exec"
)

const (
	enclaveNetworkingScriptPath = "/usr/bin/setup-enclave-networking.sh"
)

// SetupConnectivity runs the `setup-enclave-networking` script.
// It must succeed before the enclave can start up.
func SetupConnectivity() bool {
	cmd := exec.Command(enclaveNetworkingScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run() == nil
}
