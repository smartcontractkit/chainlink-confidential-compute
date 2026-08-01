package util

import (
	"net/http"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outboundproxy"
	"github.com/stretchr/testify/require"
)

func TestClassifyOutboundProxyErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "policy", err: &outboundproxy.PolicyError{Reason: "private address"}, status: http.StatusBadRequest},
		{name: "capacity", err: &outboundproxy.ProxyError{Code: outboundproxy.CodeCapacity, Op: "connect"}, status: http.StatusServiceUnavailable},
		{name: "draining", err: &outboundproxy.ProxyError{Code: outboundproxy.CodeDraining, Op: "connect"}, status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := ClassifyOutboundHTTPError(test.err)
			require.NotNil(t, classified)
			require.Equal(t, test.status, classified.StatusCode)
		})
	}
}
