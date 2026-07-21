package util

import (
	"crypto/tls"
	"net/http"
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
