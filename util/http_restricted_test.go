package util

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestRestrictedTunnelClientValidatesURLsBeforeDial(t *testing.T) {
	dialErr := errors.New("dial reached")
	var dials atomic.Int32
	client := NewRestrictedHTTPClientWithDialer(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, dialErr
	})

	for _, raw := range []string{
		"http://artifacts.example/binary.wasm",
		"https://user:secret@artifacts.example/binary.wasm",
		"https:///binary.wasm",
	} {
		_, err := client.Get(raw)
		require.Error(t, err)
		require.True(t, IsRequestBlockedError(err), raw)
	}
	require.Zero(t, dials.Load(), "blocked URLs must not reach the tunnel")

	_, err := client.Get("https://artifacts.example/binary.wasm?X-Amz-Signature=secret")
	require.ErrorIs(t, err, dialErr, "query-string signatures must remain allowed")
	require.Equal(t, int32(1), dials.Load())
}

func TestRestrictedTunnelClientRejectsRedirects(t *testing.T) {
	var requests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(rw, r, server.URL+"/next", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	serverTransport := server.Client().Transport.(*http.Transport)
	dialer := &net.Dialer{}
	client := NewRestrictedHTTPClientWithTLSAndDialer(
		serverTransport.TLSClientConfig.Clone(),
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	)

	_, err := client.Get(server.URL + "/binary.wasm")
	require.ErrorContains(t, err, "redirects are not allowed")
	require.Equal(t, int32(1), requests.Load(), "the redirect target must not be requested")
}
