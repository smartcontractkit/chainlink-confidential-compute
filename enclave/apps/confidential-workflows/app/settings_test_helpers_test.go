package app

import (
	"encoding/json"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
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

// newStorageBackedApp returns an app with a complete settings payload injected.
// The host (not the enclave) fetches workflow binaries, so no storage service is
// stood up; the rawBinary argument is ignored and kept only so existing call
// sites read naturally.
func newStorageBackedApp(t *testing.T, rawBinary []byte, opts ...Option) (types.EnclaveApp, string) {
	t.Helper()
	return newStorageBackedAppWithSettings(t, rawBinary, nil, opts...)
}

// newStorageBackedAppWithSettings is newStorageBackedApp with the injected
// settings tweaked by mutate.
func newStorageBackedAppWithSettings(t *testing.T, rawBinary []byte, mutate func(*WorkflowSettings), opts ...Option) (types.EnclaveApp, string) {
	t.Helper()

	allOpts := append([]Option{func(a *confidentialWorkflowsApp) {
		a.worker = localWorker{a}
		a.compiler = testCompiler(t)
	}}, opts...)
	a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t), allOpts...)
	settings := testSettings()
	if mutate != nil {
		mutate(&settings)
	}
	raw, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, a.(*confidentialWorkflowsApp).InjectSettings(raw))
	return a, testLocator
}

// testSettings is a complete settings payload, satisfying the fields the app
// requires.
func testSettings() WorkflowSettings {
	return WorkflowSettings{
		GatewayURL: testGatewayURL,
	}
}
