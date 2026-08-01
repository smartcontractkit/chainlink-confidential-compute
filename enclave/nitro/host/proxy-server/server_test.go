package proxyserver

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	ccvsock "github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestSOCKSProxyResolvesAndRelays(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	upstream := startEchoServer(t)
	_, port, err := net.SplitHostPort(upstream)
	require.NoError(t, err)
	startOutboundProxyTestServer(t, 5191, true)

	dialer := proxyclient.NewInsecureFixtureDialerForTests(types.ProxyParentCID, 5191)
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

func TestSOCKSProxyPublicProfileRejectsBlockedAddress(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	startOutboundProxyTestServer(t, 5192, true)

	_, err := proxyclient.NewWorkflowControlledDialer(types.ProxyParentCID, 5192).
		DialContext(context.Background(), "tcp", "127.0.0.1:443")
	require.Error(t, err)
	require.True(t, proxyclient.IsPolicyError(err), "%v", err)
}

func TestRuleSetConfiguredProfile(t *testing.T) {
	rules := ruleSet{localAddresses: map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.7"): {}}}
	require.True(t, allows(rules, types.ProxyProfileConfigured, "10.0.0.8"))
	require.False(t, allows(rules, types.ProxyProfileConfigured, "169.254.169.254"))
	require.False(t, allows(rules, types.ProxyProfileConfigured, "10.0.0.7"))
}

func TestRuleSetLocalFixtureFlag(t *testing.T) {
	require.False(t, allows(ruleSet{}, types.ProxyProfileTest, "127.0.0.1"))
	require.True(t, allows(ruleSet{allowLocalDestinationsForTests: true}, types.ProxyProfileTest, "127.0.0.1"))
}

func allows(rules ruleSet, profile types.ProxyProfile, address string) bool {
	request := &socks5.Request{
		Request: statute.Request{Command: statute.CommandConnect},
		AuthContext: &socks5.AuthContext{Payload: map[string]string{
			"username": string(profile),
		}},
		DestAddr: &statute.AddrSpec{IP: net.IP(netip.MustParseAddr(address).AsSlice())},
	}
	_, allowed := rules.Allow(context.Background(), request)
	return allowed
}

func startOutboundProxyTestServer(t *testing.T, port uint32, allowLocalDestinationsForTests bool) {
	t.Helper()
	server, err := New(allowLocalDestinationsForTests)
	require.NoError(t, err)
	listener, err := ccvsock.ListenAt(types.ProxyParentCID, port, nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			require.ErrorIs(t, err, net.ErrClosed)
		case <-time.After(time.Second):
			t.Error("outbound proxy did not stop")
		}
	})
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_, _ = io.Copy(conn, conn)
	}()
	return listener.Addr().String()
}
