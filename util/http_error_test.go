package util

import (
	"net"
	"net/http"
	"syscall"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/stretchr/testify/require"
)

func TestClassifyOutboundProxyPolicyError(t *testing.T) {
	classified := ClassifyOutboundHTTPError(&proxyclient.PolicyError{Reason: "private address"})
	require.NotNil(t, classified)
	require.Equal(t, http.StatusBadRequest, classified.StatusCode)
}

func TestClassifyOutboundHostUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct DNS failure", err: &net.DNSError{Name: "example.invalid", IsNotFound: true}},
		{name: "SOCKS host unreachable", err: syscall.EHOSTUNREACH},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := ClassifyOutboundHTTPError(test.err)
			require.NotNil(t, classified)
			require.Equal(t, http.StatusBadGateway, classified.StatusCode)
			require.Equal(t, "upstream host unreachable", classified.Body)
		})
	}
}
