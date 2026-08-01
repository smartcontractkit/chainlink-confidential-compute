package util

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// util is imported by sibling modules that do not link the Nitro VSOCK
// transport (enclave/config-tracker). Importing it here silently breaks their
// build with a missing go.sum entry, so classify transport errors through the
// behaviour interfaces in this package instead.
func TestUtilDoesNotLinkVSOCKTransport(t *testing.T) {
	deps, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	assert.NotContains(t, string(deps), "github.com/mdlayher/vsock")
}

func TestRestrictedHTTPClientsDisableKeepAlives(t *testing.T) {
	tests := map[string]func() *http.Client{
		"default roots": func() *http.Client {
			return NewRestrictedHTTPClient().Client
		},
		"custom roots": func() *http.Client {
			return NewRestrictedHTTPClientWithTLS(&tls.Config{MinVersion: tls.VersionTLS12}).Client
		},
	}

	for name, newClient := range tests {
		t.Run(name, func(t *testing.T) {
			transport, ok := newClient().Transport.(*http.Transport)
			require.True(t, ok)
			assert.True(t, transport.DisableKeepAlives)
		})
	}
}

func TestRestrictedTunnelClientPreservesHTTP1Policy(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	client := NewRestrictedHTTPClientWithDialer(dial)
	transport, ok := client.Client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Nil(t, transport.Proxy)
	require.False(t, transport.ForceAttemptHTTP2)
	require.True(t, transport.DisableKeepAlives)
	require.NotNil(t, transport.DialContext)
}
