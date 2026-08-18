package proxyclient

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyPorts(t *testing.T) {
	require.NoError(t, workflowControlledPolicy().validateAuthority("example.com", "80"))
	require.NoError(t, workflowControlledPolicy().validateAuthority("example.com", "443"))
	require.Error(t, workflowControlledPolicy().validateAuthority("example.com", "444"))
	require.NoError(t, workflowControlledPolicy().validateAuthority("example.com", "080"))
	require.Error(t, workflowControlledPolicy().validateAuthority("example.com", "0444"))

	require.NoError(t, preSignedURLPolicy().validateAuthority("example.com", "443"))
	require.NoError(t, preSignedURLPolicy().validateAuthority("example.com", "0443"))
	require.Error(t, preSignedURLPolicy().validateAuthority("example.com", "80"))
	require.Error(t, preSignedURLPolicy().validateAuthority("example.com", "8443"))
	require.NoError(t, policy{kind: policyInsecureFixture}.validateAuthority("localhost", "8080"))
}

func TestOperatorPolicyRestrictsAuthority(t *testing.T) {
	p, err := configuredEndpointPolicy("https://Gateway.Example:5002", "storage.example:2222")
	require.NoError(t, err)
	require.NoError(t, p.validateAuthority("gateway.example", "5002"))
	require.NoError(t, p.validateAuthority("storage.example", "2222"))
	require.Error(t, p.validateAuthority("other.example", "5002"))
}
