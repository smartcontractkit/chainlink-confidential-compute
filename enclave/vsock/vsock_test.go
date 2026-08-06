package vsock

import (
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
	t.Setenv(types.EnvEnclaveCID, "21")

	listener, err := Listen(5002, nil)
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

	conn, err := Dial(mdvsock.Local, 5002, nil)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, <-accepted)
}

// The parent binds the wildcard CID so it never has to discover its own, which
// is the only part of the listen path needing /dev/vsock -- a device the host
// container deliberately does not mount. The fake backend must still put that
// wildcard listener on the same loopback port a child dialling the parent CID
// reaches, or fake runs stop meeting.
func TestWildcardListenSharesTheParentRendezvous(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	t.Setenv(types.EnvEnclaveCID, "16")

	const port = 5001
	require.Equal(t, fakeTCPPort(nitroParentCID, port), fakeTCPPort(CIDAny, port),
		"a wildcard parent listener and a child dialling the parent CID must meet")
	require.Equal(t, fakeTCPPort(localCID(), port), fakeTCPPort(CIDAny, port),
		"the wildcard must resolve where localCID() used to")
}
