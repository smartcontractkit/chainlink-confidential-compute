package main

import (
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outboundproxy"
	"github.com/stretchr/testify/require"
)

// The plan requires that no environment proxy can put a second hop in front of
// the tunnel, and that the invariant be pinned rather than only argued in prose.
// util pins it for the restricted client; these are the other two tunnel-aware
// transports, the gateway's and the artifact download's, and until now nothing
// failed if the assignment was dropped.
func TestTunnelTransportAdmitsNoEnvironmentProxy(t *testing.T) {
	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, outboundproxy.Port)

	for _, disableKeepAlives := range []bool{true, false} {
		transport := tunnelTransport(dialer, disableKeepAlives)
		require.Nil(t, transport.Proxy,
			"an environment proxy must not be able to sit in front of the tunnel")
		require.NotNil(t, transport.DialContext, "the tunnel dialer must be installed")
		require.Equal(t, disableKeepAlives, transport.DisableKeepAlives)
	}
}
