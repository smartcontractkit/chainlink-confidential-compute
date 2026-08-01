package util

import (
	"net/http"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/stretchr/testify/require"
)

func TestClassifyOutboundProxyPolicyError(t *testing.T) {
	classified := ClassifyOutboundHTTPError(&proxyclient.PolicyError{Reason: "private address"})
	require.NotNil(t, classified)
	require.Equal(t, http.StatusBadRequest, classified.StatusCode)
}
