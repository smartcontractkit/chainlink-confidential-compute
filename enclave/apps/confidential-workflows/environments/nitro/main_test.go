package main

import (
	"net/http"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/require"
)

func TestRestrictedArtifactClientKeepsSafeurlWrapper(t *testing.T) {
	dialer := proxyclient.NewPreSignedURLDialer(types.ProxyParentCID, types.ProxyPort)
	client := util.NewRestrictedHTTPClientWithDialer(dialer.DialContext)
	for _, raw := range []string{
		"http://artifacts.example:443/binary.wasm",
		"https://user:secret@artifacts.example:443/binary.wasm",
	} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.Error(t, err)
		require.True(t, util.IsRequestBlockedError(err), raw)
	}
}

func TestTunnelTransport(t *testing.T) {
	dialer := proxyclient.NewWorkflowControlledDialer(types.ProxyParentCID, types.ProxyPort)

	for _, disableKeepAlives := range []bool{true, false} {
		transport := tunnelTransport(dialer, disableKeepAlives)
		require.NotNil(t, transport.DialContext, "the tunnel dialer must be installed")
		require.Equal(t, disableKeepAlives, transport.DisableKeepAlives)
		require.True(t, transport.ForceAttemptHTTP2)
	}
}
