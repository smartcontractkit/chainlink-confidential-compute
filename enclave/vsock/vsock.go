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

// CIDAny is VMADDR_CID_ANY: bind to whatever local CID this machine has. The
// parent uses it so it never has to discover its own CID, which is the only
// thing in the listen path that needs a device node.
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
	// Each fake enclave process emulates its own parent VSOCK namespace. This
	// lets concurrent fake enclaves all bind the real parent CID without sharing
	// one loopback TCP listener. A parent binding the wildcard is the same
	// rendezvous point as a child dialling the parent CID.
	if cid == nitroParentCID || cid == CIDAny {
		cid = localCID()
	}
	return getTCPPort(cid, port)
}

// Listen creates a listener. If the environment is fake, it emulates vsock over TCP.
// In fake mode, it uses the ENCLAVE_CID environment variable to determine its CID.
//
// The wildcard CID keeps a guest from having to know its own CID, and resolves
// to the same fake loopback port that localCID() did.
func Listen(port uint32, config *vsock.Config) (net.Listener, error) {
	return ListenAt(CIDAny, port, config)
}

// ListenAt creates a listener bound to an explicit local CID, which the fake TCP
// backend also uses so parent-side listeners and enclave-side dialers agree on a
// port.
//
// It must stay ListenContextID rather than vsock.Listen: Listen discovers the
// local CID by opening /dev/vsock and issuing an ioctl, and the host container
// does not mount that device, by design -- the migration adds no new device or
// privilege. Dial needs no such lookup, which is why the pre-existing inbound
// path works without it and only this listener would have failed. Binding
// CIDAny also avoids assuming what the parent's own CID is.
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
