package vsock

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/smartcontractkit/confidential-compute/types"
)

// IsFake returns true if the vsock backend is configured to emulate vsock over
// loopback TCP (i.e. the fake enclave environment).
func IsFake() bool {
	return os.Getenv(types.EnvVSOCKBackend) == types.VSOCKBackendTCP
}

// getTCPPort calculates a stable local TCP port for a given CID and VSOCK port.
func getTCPPort(cid uint32, port uint32) uint32 {
	return (cid * 1000) + (port % 10000) + 10000
}

// Listen creates a listener. If the environment is fake, it emulates vsock over TCP.
// In fake mode, it uses the ENCLAVE_CID environment variable to determine its CID.
func Listen(port uint32, config *vsock.Config) (net.Listener, error) {
	if IsFake() {
		cidStr := os.Getenv(types.EnvEnclaveCID)
		var cid uint32 = 16 // default CID if not specified
		if cidStr != "" {
			parsed, err := strconv.ParseUint(cidStr, 10, 32)
			if err == nil {
				cid = uint32(parsed)
			}
		}
		tcpPort := getTCPPort(cid, port)
		return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	}
	return vsock.Listen(port, config)
}

// Dial connects to a remote vsock listener. If the environment is fake, it emulates vsock over TCP.
// If cid is vsock.Local (1), it resolves to the local ENCLAVE_CID.
func Dial(cid uint32, port uint32, config *vsock.Config) (net.Conn, error) {
	if IsFake() {
		if cid == vsock.Local {
			cidStr := os.Getenv(types.EnvEnclaveCID)
			cid = 16 // default
			if cidStr != "" {
				parsed, err := strconv.ParseUint(cidStr, 10, 32)
				if err == nil {
					cid = uint32(parsed)
				}
			}
		}
		tcpPort := getTCPPort(cid, port)
		return net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	}
	return vsock.Dial(cid, port, config)
}
