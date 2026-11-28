package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func injectTestSettings(t *testing.T, a *confidentialWorkflowsApp, s WorkflowSettings) {
	t.Helper()
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, a.InjectSettings(raw))
}

type policyTestEmitter struct {
	recordingEmitter
	afterSnapshot func()
}

func (e *policyTestEmitter) Emit(event string, details map[string]any) {
	e.recordingEmitter.Emit(event, details)
	if event == "cre_limits_policy" && e.afterSnapshot != nil {
		e.afterSnapshot()
	}
}

func TestInjectSettings_EnforcementGate(t *testing.T) {
	a := NewTestConfidentialWorkflowsApp(sdkpb.TeeType_TEE_TYPE_AWS_NITRO, logger.Test(t)).(*confidentialWorkflowsApp)
	assert.Equal(t, map[string]any{"enforceCRELimits": false}, a.SettingsStatus())
	s := testSettings("127.0.0.1:1")
	for _, enabled := range []bool{true, false, true} {
		s.EnforceCRELimits = enabled
		injectTestSettings(t, a, s)
		assert.Equal(t, map[string]any{"enforceCRELimits": enabled}, a.SettingsStatus())
	}
	for _, raw := range []string{`{`, `{"enforceCRELimits":false}`, `{"enforceCRELimits":"false"}`} {
		require.Error(t, a.InjectSettings([]byte(raw)))
		assert.True(t, a.enforceCRELimits.Load(), "failed update preserves policy")
	}
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	var omitted map[string]any
	require.NoError(t, json.Unmarshal(raw, &omitted))
	delete(omitted, "enforceCRELimits")
	raw, err = json.Marshal(omitted)
	require.NoError(t, err)
	require.NoError(t, a.InjectSettings(raw))
	assert.False(t, a.enforceCRELimits.Load(), "omitted flag disables enforcement")

	s.EnforceCRELimits = true
	injectTestSettings(t, a, s)
	storageFactory := a.storageFactory
	a.storageFactory = func(string, bool, string, int64, time.Duration, logger.Logger) (RawFetcher, ed25519.PublicKey, error) {
		return nil, nil, errors.New("storage unavailable")
	}
	s.EnforceCRELimits = false
	raw, err = json.Marshal(s)
	require.NoError(t, err)
	require.ErrorContains(t, a.InjectSettings(raw), "storage unavailable")
	assert.True(t, a.enforceCRELimits.Load())
	a.storageFactory = storageFactory
	a.dispatcherFactory = func(GatewayConfig) (RemoteDispatcher, error) {
		return nil, errors.New("dispatcher unavailable")
	}
	require.ErrorContains(t, a.InjectSettings(raw), "dispatcher unavailable")
	assert.True(t, a.enforceCRELimits.Load())
}

func TestExecute_WASMLimitsGate(t *testing.T) {
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(buildTestWasm(t, "hello"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)
	payload, err := anypb.New(&basictrigger.Outputs{CoolOutput: "cool"})
	require.NoError(t, err)
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId: "wasm-gate", BinaryUrl: testLocator, BinaryHash: hash[:],
		SdkExecuteRequest: &sdkpb.ExecuteRequest{MaxResponseSize: 1,
			Request: &sdkpb.ExecuteRequest_Trigger{Trigger: &sdkpb.Trigger{Id: 0, Payload: payload}}},
		Limits: &confworkflowtypes.ExecutionLimits{Wasm: &confworkflowtypes.WASMLimits{ResponseLimitEnforced: proto.Bool(true)}},
	}
	data, err := proto.Marshal(execution)
	require.NoError(t, err)
	var settings WorkflowSettings
	app, _ := newStorageBackedAppWithSettings(t, binary, func(s *WorkflowSettings) { settings = *s })
	a := app.(*confidentialWorkflowsApp)
	for _, enabled := range []bool{false, true, false} {
		settings.EnforceCRELimits = enabled
		injectTestSettings(t, a, settings)
		em := &recordingEmitter{}
		out, execErr := a.Execute([32]byte{}, types.AppIDConfidentialWorkflows, data, nil, em)
		if enabled {
			require.NotNil(t, execErr, "sent response size must reject the result")
		} else {
			require.Nil(t, execErr)
			var response confworkflowtypes.ConfidentialWorkflowResponse
			require.NoError(t, proto.Unmarshal(out, &response))
			assert.Empty(t, response.GetSdkExecutionResult().GetError())
		}
		assert.Equal(t, map[string]any{"enforced": enabled, "limits_present": true}, em.lastDetails("cre_limits_policy"))
	}
}
