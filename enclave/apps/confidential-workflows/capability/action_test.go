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
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

var _ framework.ConfidentialAction[*EnclaveActionInputAdapter, *confworkflowtypes.ConfidentialWorkflowResponse] = (*mockConfidentialAction)(nil)

const (
	testWorkflowID  = "wid-123"
	testExecutionID = "e0f6c5a4b3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6"
	testOwnerHex    = "0x1234567890abcdef1234567890abcdef12345678"
	testOrgID       = "org-1"
)

// checksummedOwner is the canonical EIP-55 form; HexToAddress().String()
// returns checksummed hex, so execution.Owner must match that casing.
var checksummedOwner = util.HexToAddress("0x1234567890abcdef1234567890abcdef12345678").String()

func testMetadata() capabilities.RequestMetadata {
	return capabilities.RequestMetadata{
		WorkflowID:          testWorkflowID,
		WorkflowExecutionID: testExecutionID,
		WorkflowOwner:       testOwnerHex,
		OrgID:               testOrgID,
	}
}

func testExecution() *confworkflowtypes.WorkflowExecution {
	return &confworkflowtypes.WorkflowExecution{
		WorkflowId:  testWorkflowID,
		ExecutionId: testExecutionID,
		Owner:       checksummedOwner,
		OrgId:       testOrgID,
	}
}

func TestValidateExecutionIdentity_Match(t *testing.T) {
	assert.Empty(t, validateExecutionIdentity(testMetadata(), testExecution()))
}

func TestValidateExecutionIdentity_OwnerWithoutPrefix(t *testing.T) {
	m := testMetadata()
	m.WorkflowOwner = "1234567890abcdef1234567890abcdef12345678"
	assert.Empty(t, validateExecutionIdentity(m, testExecution()))
}

func TestValidateExecutionIdentity_Mismatches(t *testing.T) {
	cases := map[string]func(*confworkflowtypes.WorkflowExecution){
		"workflow_id": func(e *confworkflowtypes.WorkflowExecution) { e.WorkflowId = "other" },
		"execution_id": func(e *confworkflowtypes.WorkflowExecution) {
			e.ExecutionId = "0000000000000000000000000000000000000000000000000000000000000000"
		},
		"owner": func(e *confworkflowtypes.WorkflowExecution) {
			e.Owner = "0x0000000000000000000000000000000000000001"
		},
		"org_id": func(e *confworkflowtypes.WorkflowExecution) { e.OrgId = "other-org" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := testExecution()
			mutate(e)
			msg := validateExecutionIdentity(testMetadata(), e)
			assert.Contains(t, msg, name+" mismatch")
		})
	}
}

func TestExecute_RejectsIdentityMismatch(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{},
		lggr:               logger.Sugared(logger.Nop()),
	}
	e := testExecution()
	e.WorkflowId = "other"
	resp, capErr := action.Execute(context.Background(), testMetadata(), &confworkflowtypes.ConfidentialWorkflowRequest{Execution: e})
	require.Nil(t, resp)
	require.NotNil(t, capErr)
	assert.Contains(t, capErr.Error(), "workflow_id mismatch")
}

func TestExecute_RejectsNilExecution(t *testing.T) {
	action := &ConfidentialWorkflowAction{
		ConfidentialAction: &mockConfidentialAction{},
		lggr:               logger.Sugared(logger.Nop()),
	}
	resp, capErr := action.Execute(context.Background(), testMetadata(), &confworkflowtypes.ConfidentialWorkflowRequest{})
	require.Nil(t, resp)
	require.NotNil(t, capErr)
	assert.Contains(t, capErr.Error(), "execution field is required")
}


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
