package vsock

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const nitroParentCID = 3

// CIDAny is VMADDR_CID_ANY.
const CIDAny uint32 = 0xFFFFFFFF

// IsFake returns true if the vsock backend is configured to emulate vsock over
// loopback TCP (i.e. the fake enclave environment).
func IsFake() bool {
	return os.Getenv(types.EnvVSOCKBackend) == types.VSOCKBackendTCP
}

// getTCPPort calculates a stable local TCP port for a given CID and VSOCK port.
func getTCPPort(cid uint32, port uint32) uint32 {
	return (cid * 1000) + (port % 10000) + 10000
}

func fakeTCPPort(cid, port uint32) uint32 {
	// Namespace parent/wildcard ports by enclave CID in the shared fake TCP backend.
	if cid == nitroParentCID || cid == CIDAny {
		cid = localCID()
	}
	return getTCPPort(cid, port)
}

// Listen creates a listener. If the environment is fake, it emulates vsock over TCP.
// In fake mode, it uses the ENCLAVE_CID environment variable to determine its CID.
func Listen(port uint32, config *vsock.Config) (net.Listener, error) {
	if IsFake() {
		return ListenAt(CIDAny, port, config)
	}
	return vsock.Listen(port, config)
}

// ListenAt avoids local-CID discovery because the host container lacks /dev/vsock.
func ListenAt(cid, port uint32, config *vsock.Config) (net.Listener, error) {
	if IsFake() {
		tcpPort := fakeTCPPort(cid, port)
		return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	}
	return vsock.ListenContextID(cid, port, config)
}

func localCID() uint32 {
	cidStr := os.Getenv(types.EnvEnclaveCID)
	if cidStr == "" {
		return 16
	}
	parsed, err := strconv.ParseUint(cidStr, 10, 32)
	if err != nil {
		return 16
	}
	return uint32(parsed)
}

// Dial connects to a remote vsock listener. If the environment is fake, it emulates vsock over TCP.
// If cid is vsock.Local (1), it resolves to the local ENCLAVE_CID.
func Dial(cid uint32, port uint32, config *vsock.Config) (net.Conn, error) {
	if IsFake() {
		if cid == vsock.Local {
			cid = localCID()
		}
		tcpPort := fakeTCPPort(cid, port)
		return net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	}
	return vsock.Dial(cid, port, config)
}
