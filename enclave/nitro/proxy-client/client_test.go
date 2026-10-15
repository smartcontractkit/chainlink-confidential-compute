package proxyclient

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

func TestMapSOCKSHostUnreachable(t *testing.T) {
	err := errors.New("socks connect tcp vsock:5001->example.invalid:443: unknown error host unreachable")
	require.ErrorIs(t, mapSOCKSError(err), syscall.EHOSTUNREACH)
}

func TestMapSOCKSError(t *testing.T) {
	const prefix = "socks connect tcp vsock:5001->example.com:443: "
	require.ErrorIs(t, mapSOCKSError(errors.New(prefix+"unknown error connection refused")), syscall.ECONNREFUSED)
	require.True(t, IsPolicyError(mapSOCKSError(errors.New(prefix+"unknown error connection not allowed by ruleset"))))

	other := errors.New(prefix + "unknown error TTL expired")
	require.Same(t, other, mapSOCKSError(other))
}

// The host's SOCKS server selects egress rules from the profile each
// constructor sends as credentials, so each constructor must install the
// intended policy.
func TestDialerConstructorsSelectPolicy(t *testing.T) {
	configured, err := NewConfiguredEndpointDialer(3, 5001, "https://operator.example.com")
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		dialer  *Dialer
		kind    policyKind
		profile types.ProxyProfile
	}{
		{"workflow controlled", NewWorkflowControlledDialer(3, 5001), policyWorkflowControlled, types.ProxyProfilePublic},
		{"pre-signed URL", NewPreSignedURLDialer(3, 5001), policyPreSignedURL, types.ProxyProfilePublic},
		{"insecure fixture", NewInsecureFixtureDialerForTests(3, 5001), policyInsecureFixture, types.ProxyProfileTest},
		{"configured endpoint", configured, policyConfiguredEndpoint, types.ProxyProfileConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.kind, tc.dialer.policy.kind)
			assert.Equal(t, tc.profile, tc.dialer.policy.profile)
		})
	}
	assert.Equal(t, map[string]struct{}{"operator.example.com:443": {}}, configured.policy.authorities)

	_, err = NewConfiguredEndpointDialer(3, 5001)
	require.Error(t, err)
}

type socksFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f socksFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestDialContext(t *testing.T) {
	var dialed []string
	d := &Dialer{
		policy: workflowControlledPolicy(),
		socks: socksFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, network+" "+address)
			return nil, errors.New("socks connect tcp vsock:5001->" + address + ": unknown error connection not allowed by ruleset")
		}),
	}

	for _, network := range []string{"udp", "tcp6", "unix"} {
		_, err := d.DialContext(context.Background(), network, "example.com:443")
		require.ErrorContains(t, err, "supports only TCP")
	}
	_, err := d.DialContext(context.Background(), "tcp", "example.com")
	require.True(t, IsPolicyError(err), "missing port: %v", err)
	_, err = d.DialContext(context.Background(), "tcp", "example.com:22")
	require.True(t, IsPolicyError(err), "disallowed port: %v", err)
	require.Empty(t, dialed, "rejected destinations must not reach the SOCKS server")

	_, err = d.DialContext(context.Background(), "tcp4", "example.com:443")
	require.True(t, IsPolicyError(err), "host ruleset denial: %v", err)
	require.Equal(t, []string{"tcp4 example.com:443"}, dialed)
}
