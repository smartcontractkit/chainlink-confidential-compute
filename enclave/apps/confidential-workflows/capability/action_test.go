package capability

import (
	"context"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
)

var _ framework.ConfidentialAction[*EnclaveActionInputAdapter, *confworkflowtypes.ConfidentialWorkflowResponse] = (*mockConfidentialAction)(nil)

type mockConfidentialAction struct {
	enclaves []cctypes.Enclave
}

func (m *mockConfidentialAction) GetEnclaves() []cctypes.Enclave {
	return m.enclaves
}

func (m *mockConfidentialAction) Start(context.Context) error    { return nil }
func (m *mockConfidentialAction) Close() error                   { return nil }
func (m *mockConfidentialAction) HealthReport() map[string]error { return nil }
func (m *mockConfidentialAction) Name() string                   { return "mock" }
func (m *mockConfidentialAction) Description() string            { return "" }
func (m *mockConfidentialAction) Ready() error                   { return nil }
func (m *mockConfidentialAction) Initialise(context.Context, core.StandardCapabilitiesDependencies) error {
	return nil
}
func (m *mockConfidentialAction) EnsureExecutorReady(context.Context) error {
	return nil
}
func (m *mockConfidentialAction) Execute(context.Context, capabilities.RequestMetadata, *EnclaveActionInputAdapter) (*capabilities.ResponseAndMetadata[*confworkflowtypes.ConfidentialWorkflowResponse], error) {
	return nil, nil
}

func TestProvidedTees_MultipleRegionsSameType(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{enclaves: []cctypes.Enclave{
			{Region: "us-east-1", EnclaveType: cctypes.EnclaveTypeNitro},
			{Region: "eu-west-1", EnclaveType: cctypes.EnclaveTypeNitro},
		}},
		lggr: logger.Sugared(logger.Nop()),
	}

	resp, capErr := action.ProvidedTees(context.Background(), capabilities.RequestMetadata{}, &emptypb.Empty{})
	require.Nil(t, capErr)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Tee, 1)
	assert.Equal(t, sdkpb.TeeType_TEE_TYPE_AWS_NITRO, resp.Response.Tee[0].Type)
	assert.ElementsMatch(t, []string{"us-east-1", "eu-west-1"}, resp.Response.Tee[0].Regions)
}

func TestProvidedTees_SingleRegion(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{enclaves: []cctypes.Enclave{
			{Region: "us-east-1", EnclaveType: cctypes.EnclaveTypeNitro},
		}},
		lggr: logger.Sugared(logger.Nop()),
	}

	resp, capErr := action.ProvidedTees(context.Background(), capabilities.RequestMetadata{}, &emptypb.Empty{})
	require.Nil(t, capErr)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Tee, 1)
	assert.Equal(t, []string{"us-east-1"}, resp.Response.Tee[0].Regions)
}

func TestProvidedTees_EmptyInfos(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{enclaves: []cctypes.Enclave{}},
		lggr:              logger.Sugared(logger.Nop()),
	}

	resp, capErr := action.ProvidedTees(context.Background(), capabilities.RequestMetadata{}, &emptypb.Empty{})
	require.Nil(t, capErr)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Response.Tee)
}

func TestProvidedTees_UnknownEnclaveType(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{enclaves: []cctypes.Enclave{
			{Region: "us-east-1", EnclaveType: cctypes.EnclaveTypeSGX},
		}},
		lggr: logger.Sugared(logger.Nop()),
	}

	resp, capErr := action.ProvidedTees(context.Background(), capabilities.RequestMetadata{}, &emptypb.Empty{})
	require.Nil(t, capErr)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Tee, 1)
	assert.Equal(t, sdkpb.TeeType_TEE_TYPE_UNSPECIFIED, resp.Response.Tee[0].Type)
}

func TestProvidedTees_EmptyRegion(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{enclaves: []cctypes.Enclave{
			{EnclaveType: cctypes.EnclaveTypeNitro},
		}},
		lggr: logger.Sugared(logger.Nop()),
	}

	resp, capErr := action.ProvidedTees(context.Background(), capabilities.RequestMetadata{}, &emptypb.Empty{})
	require.Nil(t, capErr)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Tee, 1)
	assert.Equal(t, sdkpb.TeeType_TEE_TYPE_AWS_NITRO, resp.Response.Tee[0].Type)
	assert.Empty(t, resp.Response.Tee[0].Regions)
}
