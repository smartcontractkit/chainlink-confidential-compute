package vsock

import (
	"net"
	"strconv"
	"testing"

	mdvsock "github.com/mdlayher/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
)

func TestListenAtFakeCID(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	t.Setenv(types.EnvEnclaveCID, "22")

	listener, err := ListenAt(3, 5001, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()

	conn, err := Dial(3, 5001, nil)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, <-accepted)
}

func TestFakeParentListenersAreNamespacedByEnclaveCID(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	t.Setenv(types.EnvEnclaveCID, "23")
	first, err := ListenAt(nitroParentCID, 5001, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, first.Close()) })

	t.Setenv(types.EnvEnclaveCID, "24")
	second, err := ListenAt(nitroParentCID, 5001, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.Close()) })
}

func TestListenUsesEnclaveCIDInFakeMode(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	cid, port := availableFakeVSOCKAddress(t)
	t.Setenv(types.EnvEnclaveCID, cid)

	listener, err := Listen(port, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()

	conn, err := Dial(mdvsock.Local, port, nil)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, <-accepted)
}

func availableFakeVSOCKAddress(t *testing.T) (string, uint32) {
	t.Helper()

	// Map an OS-assigned TCP port back to fake VSOCK coordinates.
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	tcpPort := uint32(probe.Addr().(*net.TCPAddr).Port) //nolint:gosec // TCP ports fit in uint32
	require.NoError(t, probe.Close())
	require.Greater(t, tcpPort, uint32(10000))

	offset := tcpPort - 10000
	return strconv.FormatUint(uint64(offset/1000), 10), offset % 1000
}

func TestWildcardListenSharesTheParentRendezvous(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	t.Setenv(types.EnvEnclaveCID, "16")

	const port = 5001
	require.Equal(t, fakeTCPPort(nitroParentCID, port), fakeTCPPort(CIDAny, port),
		"a wildcard parent listener and a child dialling the parent CID must meet")
	require.Equal(t, fakeTCPPort(localCID(), port), fakeTCPPort(CIDAny, port),
		"the wildcard must resolve where localCID() used to")
}
