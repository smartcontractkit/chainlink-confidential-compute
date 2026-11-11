package app

import (
	"encoding/json"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/require"
)

// testLocator is the artifact id tests place in WorkflowExecution.BinaryUrl.
// The host fetches binaries, so nothing dials it from inside the enclave.
const testLocator = "test-artifact-id"

// testGatewayURL satisfies the required gatewayUrl setting. Tests that exercise
// remote dispatch supply their own dispatcher (WithRemoteDispatcher) or factory,
// so nothing dials this.
const testGatewayURL = "http://gateway.invalid"

func newConfiguredApp(t *testing.T, mutate func(*WorkflowSettings), opts ...Option) *confidentialWorkflowsApp {
	t.Helper()

	a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), opts...).(*confidentialWorkflowsApp)
	settings := testSettings()
	if mutate != nil {
		mutate(&settings)
	}
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, a.InjectSettings(raw))
	return a
}

// testSettings is a complete settings payload, satisfying the fields the app
// requires.
func testSettings() WorkflowSettings {
	return WorkflowSettings{
		GatewayURL: testGatewayURL,
	}
}
