package framework_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework"
	enclaveclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave-client"
	enclavetypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/types/frameworktypes"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	p2ptypes "github.com/smartcontractkit/libocr/ragep2p/types"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/actions/vault"
	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	"github.com/smartcontractkit/chainlink-common/pkg/contexts"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/ratelimit"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"

	"github.com/smartcontractkit/capabilities/libs/testutils"
)

var mockEnclaveID = [32]byte{9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

var mockPeerID1 = p2ptypes.PeerID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
var mockPeerID2 = p2ptypes.PeerID{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33}
var mockPeerID3 = p2ptypes.PeerID{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}

// PRIV-392: re-enable this function when SHA-based WorkflowExecutionID is restored
// func testSHA(strs ...string) string {
// 	h := sha256.New()
// 	for _, s := range strs {
// 		h.Write([]byte(s))
// 	}
// 	return hex.EncodeToString(h.Sum(nil))
// }

// MockEnclaveClient is a simple struct that implements the EnclaveClient interface.
type MockEnclaveClient struct {
	callCount int

	GetPublicKeysFunc func(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error)
	ExecuteBatchFunc  func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error)
	UpdateNodesFunc   func(nodes []enclavetypes.Enclave)
	UpdateConfigFunc  func(ctx context.Context, update enclavetypes.UpdateConfigRequest) error
	GetConfigsFunc    func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error)
}

func (m *MockEnclaveClient) GetPublicKeys(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error) {
	if m.GetPublicKeysFunc != nil {
		return m.GetPublicKeysFunc(ctx, requestID, checkRequirements)
	}
	return []enclavetypes.EnclavePublicKeyData{
		{
			PublicKeyResponse: enclavetypes.PublicKeyResponse{
				PublicKeys: [][]byte{
					[]byte("mock_public_key_bytes_1"),
					[]byte("mock_public_key_bytes_2"),
				},
				CreationTimes: []time.Time{time.Now(), time.Now().Add(-time.Hour)},
				TTLs:          []time.Duration{time.Hour * 24, time.Hour * 48},
				Config: enclavetypes.EnclaveConfig{
					Signers: [][]byte{mockPeerID1[:], mockPeerID2[:]},
				},
				Attestation: []byte("mock_attestation_data"),
			},
			EnclaveID: mockEnclaveID,
		},
	}, nil
}

func (m *MockEnclaveClient) ExecuteBatch(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
	if m.ExecuteBatchFunc != nil {
		return m.ExecuteBatchFunc(ctx, reqs, enclaveIDs)
	}
	return nil, errors.New("ExecuteBatchFunc not implemented for MockEnclaveClient")
}

func (m *MockEnclaveClient) commonExecuteBatchReturn(t *testing.T) ([]enclavetypes.ExecuteResponse, error) {
	testOutput := &framework.TestOutput{
		Result:  "First response",
		Success: true,
	}

	outputBytes, err := json.Marshal(testOutput)
	assert.NoError(t, err)

	return []enclavetypes.ExecuteResponse{
		{
			RequestID: [32]byte{1, 2, 3},
			Output:    outputBytes, // Use the JSON marshaled Any bytes
			Config: enclavetypes.EnclaveConfig{
				Signers:         [][]byte{mockPeerID1[:], mockPeerID2[:]},
				MasterPublicKey: []byte("master_pub_key_1"),
				T:               1,
				F:               0,
			},
			Attestation: []byte(""),
			Metrics: map[string]any{
				"request_started":   map[string]any{"endpoint": "execute"},
				"request_completed": map[string]any{"endpoint": "execute", "duration_seconds": 0.123},
			},
		}}, nil
}

func (m *MockEnclaveClient) UpdateNodes(nodes []enclavetypes.Enclave) {
	if m.UpdateNodesFunc != nil {
		m.UpdateNodesFunc(nodes)
	}
}

func (m *MockEnclaveClient) UpdateConfig(ctx context.Context, update enclavetypes.UpdateConfigRequest) error {
	if m.UpdateConfigFunc != nil {
		return m.UpdateConfigFunc(ctx, update)
	}
	return nil
}

func (m *MockEnclaveClient) GetConfigs(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
	if m.GetConfigsFunc != nil {
		return m.GetConfigsFunc(ctx)
	}
	return nil, nil
}

func (m *MockEnclaveClient) GetCacheStats() map[string]interface{} { return nil }

func (m *MockEnclaveClient) Close() error { return nil }

type mockKeystore struct {
	core.UnimplementedKeystore
	accounts     []string
	signFunc     func(ctx context.Context, account string, msg []byte) ([]byte, error)
	accountsFunc func(ctx context.Context) ([]string, error)
	decryptFunc  func(ctx context.Context, account string, ciphertext []byte) ([]byte, error)
}

func (m *mockKeystore) Accounts(ctx context.Context) ([]string, error) {
	if m.accountsFunc != nil {
		return m.accountsFunc(ctx)
	}
	return m.accounts, nil
}

func (m *mockKeystore) Sign(ctx context.Context, account string, msg []byte) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, account, msg)
	}
	return []byte(""), nil
}

func (m *mockKeystore) Decrypt(ctx context.Context, account string, ciphertext []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, account, ciphertext)
	}
	return []byte("decrypted-api-key"), nil
}

func getMockKeystore() *mockKeystore {
	return &mockKeystore{
		accounts: []string{core.StandardCapabilityAccount},
		signFunc: func(ctx context.Context, account string, msg []byte) ([]byte, error) {
			return []byte("test-signature"), nil
		},
	}
}

// MockVaultDONCapability implements core.ExecutableCapability for testing VaultDON interactions.
type MockVaultDONCapability struct {
	ExecuteFunc func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error)
	InfoFunc    func(ctx context.Context) (capabilities.CapabilityInfo, error)
}

// UnregisterFromWorkflow implements the required method for capabilities.ExecutableCapability.
func (m *MockVaultDONCapability) UnregisterFromWorkflow(ctx context.Context, workflow capabilities.UnregisterFromWorkflowRequest) error {
	// No-op for testing
	return nil
}

// RegisterToWorkflow implements the required method for capabilities.ExecutableCapability.
func (m *MockVaultDONCapability) RegisterToWorkflow(ctx context.Context, workflow capabilities.RegisterToWorkflowRequest) error {
	// No-op for testing
	return nil
}

// Info implements core.ExecutableCapability.
func (m *MockVaultDONCapability) Info(ctx context.Context) (capabilities.CapabilityInfo, error) {
	if m.InfoFunc != nil {
		return m.InfoFunc(ctx)
	}
	return capabilities.CapabilityInfo{
		ID:             "mock-vault-don@1.0.0",
		CapabilityType: capabilities.CapabilityTypeAction,
		Description:    "Mock VaultDON for testing",
		DON: &capabilities.DON{
			ID: 1,
			F:  0, // F=0 gives threshold=1 (2*F+1), works with 2 shares
		},
	}, nil
}

// Execute implements core.ExecutableCapability.
func (m *MockVaultDONCapability) Execute(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	if m.ExecuteFunc != nil {
		return m.ExecuteFunc(ctx, req)
	}
	return capabilities.CapabilityResponse{}, errors.New("ExecuteFunc not implemented for MockVaultDONCapability")
}

// MockCapabilitiesRegistry implements core.CapabilitiesRegistry for testing with NewRealExecutor.
type MockCapabilitiesRegistry struct {
	core.UnimplementedCapabilitiesRegistry
	LocalNodeFunc           func(ctx context.Context) (capabilities.Node, error)
	ConfigForCapabilityFunc func(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error)
	GetExecutableFunc       func(ctx context.Context, ID string) (capabilities.ExecutableCapability, error)
}

func (m *MockCapabilitiesRegistry) LocalNode(ctx context.Context) (capabilities.Node, error) {
	if m.LocalNodeFunc != nil {
		return m.LocalNodeFunc(ctx)
	}
	return capabilities.Node{}, errors.New("LocalNodeFunc not implemented")
}

func (m *MockCapabilitiesRegistry) ConfigForCapability(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error) {
	if m.ConfigForCapabilityFunc != nil {
		return m.ConfigForCapabilityFunc(ctx, capabilityID, donID)
	}
	return capabilities.CapabilityConfiguration{}, errors.New("ConfigForCapabilityFunc not implemented")
}

func (m *MockCapabilitiesRegistry) GetExecutable(ctx context.Context, ID string) (capabilities.ExecutableCapability, error) {
	if m.GetExecutableFunc != nil {
		return m.GetExecutableFunc(ctx, ID)
	}
	return nil, errors.New("GetExecutableFunc not implemented")
}

// getMockCapabilitiesRegistry returns a default mock registry suitable for test executors.
// It provides the minimum required behavior for EnsureFreshEnclaves to work.
func getMockCapabilitiesRegistry(t *testing.T, mockVaultDON framework.VaultDON) *MockCapabilitiesRegistry {
	return &MockCapabilitiesRegistry{
		LocalNodeFunc: func(ctx context.Context) (capabilities.Node, error) {
			return capabilities.Node{
				WorkflowDON: capabilities.DON{
					ID:      1,
					F:       0,
					Members: []p2ptypes.PeerID{mockPeerID1, mockPeerID2},
				},
				PeerID: nil,
			}, nil
		},
		ConfigForCapabilityFunc: func(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error) {
			enclavesList := enclavetypes.EnclavesList{
				Enclaves: []enclavetypes.Enclave{
					{
						EnclaveID:     mockEnclaveID,
						EnclaveURL:    "https://mock-enclave.example.com",
						EnclaveType:   "nitro",
						TrustedValues: [][]byte{[]byte("{}")},
						Region:        "us-west-2",
					},
				},
			}
			wrappedConfig, err := values.WrapMap(enclavesList)
			require.NoError(t, err)
			return capabilities.CapabilityConfiguration{
				DefaultConfig: wrappedConfig,
			}, nil
		},
		GetExecutableFunc: func(ctx context.Context, ID string) (capabilities.ExecutableCapability, error) {
			if ID == vault.CapabilityID {
				return mockVaultDON.Capability, nil
			}
			return nil, fmt.Errorf("unknown capability ID: %s", ID)
		},
	}
}

// MockMetrics is a stub implementation of types.Emitter for testing.
type MockMetrics struct {
	// CallCounts tracks how many times each event was emitted
	CallCounts map[string]int

	// EmitRecords tracks all calls to Emit with their details
	EmitRecords map[string][]map[string]any
}

// NewMockMetrics initializes the map fields to prevent nil panics during use.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		CallCounts:  make(map[string]int),
		EmitRecords: make(map[string][]map[string]any),
	}
}

// Emit implements the types.Emitter interface.
func (m *MockMetrics) Emit(event string, details map[string]any) {
	m.CallCounts[event] += 1
	m.EmitRecords[event] = append(m.EmitRecords[event], details)
}

// --- Test Helper Functions ---

// AssertCalledNTimes verifies a metric was called the expected number of times (simple count).
func AssertCalledNTimes(t *testing.T, m *MockMetrics, name string, expected int) {
	t.Helper()
	count, ok := m.CallCounts[name]
	if expected == 0 && !ok {
		return
	}
	if !assert.True(t, ok, "Metric '%s' was expected to be called, but was not found.", name) {
		return
	}
	assert.Equal(t, expected, count, "Metric '%s' was expected to be called %d times, but was called %d times.", name, expected, count)
}

// AssertCalledWithDetails verifies an event was emitted with specific details.
func AssertCalledWithDetails(t *testing.T, m *MockMetrics, name string, expectedDetails map[string]any) {
	t.Helper()

	records, ok := m.EmitRecords[name]
	if !assert.True(t, ok, "Event '%s' was expected to be emitted, but was not found.", name) {
		return
	}

	var foundMatch bool
	for _, record := range records {
		if assert.ObjectsAreEqual(expectedDetails, record) {
			foundMatch = true
			break
		}
	}

	assert.True(t, foundMatch, "Event '%s' was emitted, but none of the calls matched the expected details:\nExpected: %v\nRecorded Calls: %v", name, expectedDetails, m.EmitRecords[name])
}

func getTestExecutorInput() *framework.TestActionInput {
	// Create test-specific input
	testInput := &framework.TestInput{
		TestField:  "test-value",
		TestArray:  []string{"item1", "item2"},
		TestNumber: 42,
	}
	ignoredOwner := "ignored-owner"
	return &framework.TestActionInput{
		VaultDonSecrets: []*frameworktypes.SecretIdentifier{
			{
				Key:       "my-secret-api-key",
				Namespace: "my-namespace",
				Owner:     &ignoredOwner,
			},
		},
		Input: testInput,
	}
}

func getDefaultRateLimiter() *ratelimit.RateLimiter {
	rateLimiter, _ := ratelimit.NewRateLimiter(ratelimit.RateLimiterConfig{
		GlobalRPS:      framework.DefaultGlobalRPS,
		GlobalBurst:    framework.DefaultGlobalBurst,
		PerSenderRPS:   framework.DefaultWorkflowOwnerRPS,
		PerSenderBurst: framework.DefaultWorkflowOwnerBurst,
	})
	return rateLimiter
}

func getValidGetSecretsResponse() *vault.GetSecretsResponse {
	return &vault.GetSecretsResponse{
		Responses: []*vault.SecretResponse{
			{
				Id: &vault.SecretIdentifier{
					Key:       "my-secret-api-key",
					Namespace: "my-namespace",
					Owner:     "0x0000000000000000000000000000000000000000",
				},
				Result: &vault.SecretResponse_Data{
					Data: &vault.SecretData{
						EncryptedValue: hex.EncodeToString([]byte("encrypted_secret_data_for_my-secret-id")),
						EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
							{
								Shares:        []string{hex.EncodeToString([]byte("share1_for_my-secret-id")), hex.EncodeToString([]byte("share2_for_my-secret-id"))},
								EncryptionKey: string([]byte("mock_public_key_bytes_1")),
							},
						},
					},
				},
			},
		},
	}
}

func getValidGetSecretsResponseWithBinaryShares() *vault.GetSecretsResponse {
	shares := &vault.EncryptedShares{
		EncryptionKey: string([]byte("mock_public_key_bytes_1")),
	}
	shares.BinaryShares = [][]byte{[]byte("share1_for_my-secret-id"), []byte("share2_for_my-secret-id")}
	return &vault.GetSecretsResponse{
		Responses: []*vault.SecretResponse{
			{
				Id: &vault.SecretIdentifier{
					Key:       "my-secret-api-key",
					Namespace: "my-namespace",
					Owner:     "0x0000000000000000000000000000000000000000",
				},
				Result: &vault.SecretResponse_Data{
					Data: &vault.SecretData{
						EncryptedValue:               hex.EncodeToString([]byte("encrypted_secret_data_for_my-secret-id")),
						EncryptedDecryptionKeyShares: []*vault.EncryptedShares{shares},
					},
				},
			},
		},
	}
}

const (
	WORKFLOW_ID           = "test-workflow-id"
	WORKFLOW_EXECUTION_ID = "test-workflow-execution-id"
	WORKFLOW_OWNER        = "test-owner"
	WORKFLOW_ORG_ID       = "test-org-id"
	WORKFLOW_NAME         = "test-workflow-name"
	TEST_NODE_ID          = "test-node-id-12345"
)

func setupAndExecuteExecutor(t *testing.T,
	mockEnclaveClient *MockEnclaveClient,
	mockVaultDON framework.VaultDON,
	mockMetrics *MockMetrics,
	ratelimiter *ratelimit.RateLimiter,
	maxRetries int,
	retryBackoffSeconds int) ([]byte, error) {

	executor := framework.NewTestExecutor(
		logger.Test(t),
		getMockKeystore(),
		mockEnclaveClient,
		mockVaultDON,
		mockMetrics,
		ratelimiter,
		maxRetries,
		retryBackoffSeconds,
		"test-capability-id",
		true,
		TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, mockVaultDON),
	)

	ctx := context.Background()
	ctx = contexts.WithCRE(ctx, contexts.CRE{Org: WORKFLOW_ORG_ID})
	_, removeWorkflow := testutils.NewWorkflow(ctx, testutils.WorkflowParams{
		T:     t,
		Owner: "owner1",
	})
	defer removeWorkflow(ctx)

	actionInput := getTestExecutorInput()
	protoBytes, err := proto.Marshal(actionInput.GetInput())
	require.NoError(t, err)

	return executor.Execute(ctx, protoBytes, actionInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
		WorkflowID:          WORKFLOW_ID,
		WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
		WorkflowName:        WORKFLOW_NAME,
		WorkflowOwner:       WORKFLOW_OWNER,
		OrgID:               WORKFLOW_ORG_ID,
	})
}

func AssertBasicOutputValid(t *testing.T, testOutput *framework.TestOutput) {
	assert.Equal(t, "First response", testOutput.Result, "Expected result to match")
	assert.Equal(t, true, testOutput.Success, "Expected success to be true")
}

// staticSettings is a settings.Getter that returns a fixed string for every
// key. Used by tests to force cresettings gates into a known state.
type staticSettings struct{ value string }

func (s staticSettings) GetScoped(_ context.Context, _ settings.Scope, _ string) (string, error) {
	return s.value, nil
}

func TestExecutor_Execute(t *testing.T) {
	t.Run("executor executes without error", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		vaultDONCallCount := 0
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONCallCount++
			assert.Equal(t, vault.MethodGetSecrets, req.Method, "Expected VaultDON method to be GetSecrets")
			assert.Equal(t, WORKFLOW_EXECUTION_ID, req.Metadata.WorkflowExecutionID, "Expected WorkflowExecutionID to match")
			// On retry (second VaultDON call), ReferenceID should be set
			if vaultDONCallCount == 1 {
				// First attempt - ReferenceID should be original/empty
				assert.Equal(t, "", req.Metadata.ReferenceID, "Expected ReferenceID to be empty on first attempt")
			} else {
				// Retry attempt - ReferenceID should be set to retry template
				assert.Equal(t, "confidential-retry-1", req.Metadata.ReferenceID, "Expected ReferenceID to be set on retry")
			}
			assert.Equal(t, WORKFLOW_OWNER, req.Metadata.WorkflowOwner, "Expected WorkflowOwner to match")
			assert.Equal(t, WORKFLOW_ID, req.Metadata.WorkflowID, "Expected WorkflowID to match")
			assert.Equal(t, WORKFLOW_NAME, req.Metadata.WorkflowName, "Expected WorkflowName to match")

			var getSecretsReq vault.GetSecretsRequest
			err := req.Payload.UnmarshalTo(&getSecretsReq)
			require.NoError(t, err, "Failed to unmarshal VaultDON request payload")

			assert.Len(t, getSecretsReq.Requests, 1, "Expected one secret request")
			// WORKFLOW_OWNER ("test-owner") is non-hex, so HexToAddress maps it
			// to the zero address (mirrors the sibling out-of-order test below).
			wantOwner := "0x0000000000000000000000000000000000000000"
			assert.Equal(t, wantOwner, getSecretsReq.Requests[0].GetId().GetOwner(), "Expected derived secret owner addr from workflow metadata")
			assert.Equal(t, "my-secret-api-key", getSecretsReq.Requests[0].GetId().GetKey(), "Expected secret ID to match")
			assert.Len(t, getSecretsReq.Requests[0].GetEncryptionKeys(), 1, "Expected one encryption key")
			assert.Equal(t, hex.EncodeToString([]byte("mock_public_key_bytes_1")), getSecretsReq.Requests[0].GetEncryptionKeys()[0], "Expected encryption key to match enclave public key")

			respAny, err := anypb.New(getValidGetSecretsResponse())
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}

		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			assert.Equal(t, len(reqs), 1, "Expected one signed compute request")
			assert.Equal(t, sha256.Sum256([]byte(WORKFLOW_EXECUTION_ID)), reqs[0].RequestID, "Expected RequestID to remain sha256(workflow execution ID)")
			assert.Equal(t, WORKFLOW_EXECUTION_ID, reqs[0].ApplicationRequestID, "Expected ApplicationRequestID to carry the workflow execution ID")
			assert.Equal(t, 1, len(reqs[0].Ciphertexts), "Expected one ciphertext in the request")
			assert.Equal(t, 1, len(reqs[0].CiphertextNames), "Expected one ciphertext name in the request")
			assert.Equal(t, "my-secret-api-key", reqs[0].CiphertextNames[0], "Expected template ciphertext name to match")
			assert.Equal(t, 1, len(reqs[0].EncryptedDecryptionKeyShares), "Expected 1 set of shares in the request")
			assert.Equal(t, 2, len(reqs[0].EncryptedDecryptionKeyShares[0]), "Expected 2 shares per ciphertext in the request")
			assert.Equal(t, []byte("test-signature"), reqs[0].Signature, "Expected secret ID to match")

			publicDataBytes := reqs[0].PublicData
			assert.NotNil(t, publicDataBytes, "Expected public data to be set in the request")
			var testInput framework.TestInput
			err := proto.Unmarshal(publicDataBytes, &testInput)
			assert.NoError(t, err, "Failed to unmarshal public data")
			assert.Equal(t, "test-value", testInput.TestField, "Expected TestField to match")
			assert.Equal(t, []string{"item1", "item2"}, testInput.TestArray, "Expected TestArray to match")
			assert.Equal(t, int32(42), testInput.TestNumber, "Expected TestNumber to match")

			if mockEnclaveClient.callCount == 0 {
				mockEnclaveClient.callCount++
				return nil, errors.New("simulated enclave client error")
			}
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		mockMetrics := NewMockMetrics()

		executeOutput, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, mockMetrics, getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.NoError(t, err)
		assert.NotNil(t, executeOutput, "Expected non-nil output from executor")
		AssertCalledNTimes(t, mockMetrics, "requests_received_total", 1)
		AssertCalledNTimes(t, mockMetrics, "requests_completed_total", 1)
		AssertCalledNTimes(t, mockMetrics, "vault_don_error", 0)
		AssertCalledNTimes(t, mockMetrics, "compute_request_signature_error", 0)
		// MockEnclaveClient is set to error once before succeeding
		AssertCalledNTimes(t, mockMetrics, "execute_error", 1)
		// Verify execute_error includes enclave.id and node.id
		require.Contains(t, mockMetrics.EmitRecords, "execute_error")
		assert.NotEmpty(t, mockMetrics.EmitRecords["execute_error"][0]["enclave.id"], "execute_error should include enclave.id")
		assert.Equal(t, TEST_NODE_ID, mockMetrics.EmitRecords["execute_error"][0]["node.id"], "execute_error should include node.id")
		// execute_error carries the enclave-execute duration.
		assert.Contains(t, mockMetrics.EmitRecords["execute_error"][0], "duration_seconds", "execute_error should include duration_seconds")
		assert.GreaterOrEqual(t, mockMetrics.EmitRecords["execute_error"][0]["duration_seconds"].(float64), 0.0)

		// execute_total is emitted exactly once on success: outcome=success, with
		// enclave.id and a non-negative duration. Asserting "once" also guards
		// against a double-emit regression.
		AssertCalledNTimes(t, mockMetrics, "execute_total", 1)
		require.Contains(t, mockMetrics.EmitRecords, "execute_total")
		assert.Equal(t, "success", mockMetrics.EmitRecords["execute_total"][0]["outcome"])
		assert.NotEmpty(t, mockMetrics.EmitRecords["execute_total"][0]["enclave.id"], "execute_total should include enclave.id on success")
		assert.Equal(t, TEST_NODE_ID, mockMetrics.EmitRecords["execute_total"][0]["node.id"])
		assert.GreaterOrEqual(t, mockMetrics.EmitRecords["execute_total"][0]["duration_seconds"].(float64), 0.0)

		// Verify enclave metrics were forwarded through OTel with correct content
		require.Contains(t, mockMetrics.EmitRecords, "request_started", "enclave metrics should be forwarded")
		require.Contains(t, mockMetrics.EmitRecords, "request_completed", "enclave metrics should be forwarded")

		// Verify request_completed includes duration and attributes
		completedCalls := mockMetrics.EmitRecords["request_completed"]
		require.Len(t, completedCalls, 1)
		assert.Equal(t, 0.123, completedCalls[0]["duration_seconds"], "duration should match mock value")
		assert.NotEmpty(t, completedCalls[0]["workflow.owner"], "enclave metrics should include workflow.owner")
		assert.NotEmpty(t, completedCalls[0]["enclave.id"], "enclave metrics should include enclave.id")
		assert.Equal(t, WORKFLOW_NAME, completedCalls[0]["workflow.name"], "enclave metrics should include workflow.name")
			assert.Equal(t, "enclave", completedCalls[0]["component"], "enclave metrics should include component tag")
		assert.Equal(t, WORKFLOW_ORG_ID, completedCalls[0]["org.id"], "enclave metrics should include org.id")

		var testOutput framework.TestOutput
		err = json.Unmarshal(executeOutput, &testOutput)
		assert.NoError(t, err)
		AssertBasicOutputValid(t, &testOutput)
	})

	// The next two sub-tests pin the behavior of applyPropagatedOrgIDToVault.
	// Default cresettings has PropagateOrgIDInRequestMetadata=false, so OrgID
	// must be stripped from the metadata that reaches the Vault DON. When the
	// gate is flipped on via a Settings layer, OrgID must survive.

	t.Run("executor clears OrgID on Vault DON request when gate is disabled", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			assert.Equal(t, WORKFLOW_OWNER, req.Metadata.WorkflowOwner, "WorkflowOwner should always survive")
			assert.Equal(t, "", req.Metadata.OrgID, "OrgID must be cleared when PropagateOrgIDInRequestMetadata is disabled")
			respAny, err := anypb.New(getValidGetSecretsResponse())
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")

			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}
		executor := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClient, mockVaultDON,
			NewMockMetrics(), getDefaultRateLimiter(),
			framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds,
			"test-capability-id", true, TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)

		ctx := contexts.WithCRE(context.Background(), contexts.CRE{Org: WORKFLOW_ORG_ID})
		_, removeWorkflow := testutils.NewWorkflow(ctx, testutils.WorkflowParams{T: t, Owner: "owner1"})
		defer removeWorkflow(ctx)

		actionInput := getTestExecutorInput()
		protoBytes, err := proto.Marshal(actionInput.GetInput())
		require.NoError(t, err)

		output, err := executor.Execute(ctx, protoBytes, actionInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:          WORKFLOW_ID,
			WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
			WorkflowName:        WORKFLOW_NAME,
			WorkflowOwner:       WORKFLOW_OWNER,
			OrgID:               WORKFLOW_ORG_ID,
		})
		require.NoError(t, err)
		require.NotNil(t, output, "Expected non-nil output from executor")
	})

	t.Run("executor preserves OrgID on Vault DON request when gate is enabled", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			assert.Equal(t, WORKFLOW_OWNER, req.Metadata.WorkflowOwner, "WorkflowOwner should always survive")
			assert.Equal(t, WORKFLOW_ORG_ID, req.Metadata.OrgID, "OrgID must survive when PropagateOrgIDInRequestMetadata is enabled")
			respAny, err := anypb.New(getValidGetSecretsResponse())
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}
		executor := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClient, mockVaultDON,
			NewMockMetrics(), getDefaultRateLimiter(),
			framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds,
			"test-capability-id", true, TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)
		// Force PropagateOrgIDInRequestMetadata to true via a Settings layer that
		// returns "true" for every key.
		executor.SetLimitsFactoryForTesting(limits.Factory{Settings: staticSettings{value: "true"}})

		ctx := contexts.WithCRE(context.Background(), contexts.CRE{Org: WORKFLOW_ORG_ID})
		_, removeWorkflow := testutils.NewWorkflow(ctx, testutils.WorkflowParams{T: t, Owner: "owner1"})
		defer removeWorkflow(ctx)

		actionInput := getTestExecutorInput()
		protoBytes, err := proto.Marshal(actionInput.GetInput())
		require.NoError(t, err)

		output, err := executor.Execute(ctx, protoBytes, actionInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:          WORKFLOW_ID,
			WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
			WorkflowName:        WORKFLOW_NAME,
			WorkflowOwner:       WORKFLOW_OWNER,
			OrgID:               WORKFLOW_ORG_ID,
		})
		require.NoError(t, err)
		require.NotNil(t, output, "Expected non-nil output from executor")
	})

	t.Run("executor executes with error from VaultDON", func(t *testing.T) {
		mockEnclaveClient := &MockEnclaveClient{}

		// --- Mock VaultDON Capability that returns an error ---
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			return capabilities.CapabilityResponse{}, errors.New("simulated VaultDON error")
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get encrypted decryption key shares from VaultDON: failed to execute VaultDON capability: simulated VaultDON error")
	})

	t.Run("executor executes with VaultDON returning secret error", func(t *testing.T) {
		mockEnclaveClient := &MockEnclaveClient{}

		// --- Mock VaultDON Capability that returns a secret error ---
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONResponsePayload := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key: "my-secret-api-key",
						},
						Result: &vault.SecretResponse_Error{
							Error: "secret not found",
						},
					},
				},
			}

			respAny, err := anypb.New(vaultDONResponsePayload)
			require.NoError(t, err)

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VaultDON returned an error for secret request at index 0 with key my-secret-api-key: secret not found")
		// VaultDON per-secret errors with anything other than the system fallback string are
		// classified as user errors (caperrors.InvalidArgument) so the workflow engine routes
		// them to platform_engine_capabilities_user_errors instead of _failures.
		var capErr caperrors.Error
		require.True(t, errors.As(err, &capErr), "expected error to unwrap into caperrors.Error")
		assert.Equal(t, caperrors.OriginUser, capErr.Origin())
		assert.Equal(t, caperrors.InvalidArgument, capErr.Code())
	})

	t.Run("executor executes with VaultDON returning less number of shares than the threshold value", func(t *testing.T) {
		mockEnclaveClient := &MockEnclaveClient{}

		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		// --- Mock VaultDON Capability that returns a secret error ---
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONResponsePayload := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key:       "my-secret-api-key",
							Namespace: "my-namespace",
							Owner:     "0x0000000000000000000000000000000000000000",
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_secret_data_for_my-secret-id")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share1_for_my-secret-id")), hex.EncodeToString([]byte("share2_for_my-secret-id"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
				},
			}

			respAny, err := anypb.New(vaultDONResponsePayload)
			require.NoError(t, err)

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}
		// Set InfoFunc to return F=1 so threshold = 2*1+1 = 3
		mockVaultDONCapability.InfoFunc = func(ctx context.Context) (capabilities.CapabilityInfo, error) {
			return capabilities.CapabilityInfo{
				ID:             "mock-vault-don@1.0.0",
				CapabilityType: capabilities.CapabilityTypeAction,
				Description:    "Mock VaultDON for testing",
				DON: &capabilities.DON{
					ID: 1,
					F:  1, // F=1 gives threshold=3 (2*F+1)
				},
			}, nil
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 3,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get encrypted decryption key shares from VaultDON: not enough encrypted decryption key shares for secret my-secret-api-key, expected at least 3, got 2")
	})

	t.Run("executor rejects VaultDON response with duplicate secret keys", func(t *testing.T) {
		mockEnclaveClient := &MockEnclaveClient{}

		expectedOwner := "0x0000000000000000000000000000000000000000"

		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			// Return a response with duplicate secret keys
			vaultDONResponsePayload := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key:       "my-secret-api-key",
							Namespace: "my-namespace",
							Owner:     expectedOwner,
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value_1")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share1"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
					{
						Id: &vault.SecretIdentifier{
							Key:       "my-secret-api-key", // Duplicate key!
							Namespace: "my-namespace",
							Owner:     expectedOwner,
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value_2")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share2"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
				},
			}

			respAny, err := anypb.New(vaultDONResponsePayload)
			require.NoError(t, err)

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), 1, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate VaultDON response for secret key my-secret-api-key at index 1")
	})

	t.Run("executor rejects VaultDON response with missing secret identifier", func(t *testing.T) {
		mockEnclaveClient := &MockEnclaveClient{}

		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			// Return a response with a missing/empty secret identifier
			vaultDONResponsePayload := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key:       "", // Empty key
							Namespace: "my-namespace",
							Owner:     "0x0000000000000000000000000000000000000000",
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share1"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
				},
			}

			respAny, err := anypb.New(vaultDONResponsePayload)
			require.NoError(t, err)

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), 1, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VaultDON response at index 0 is missing a valid secret identifier")
	})

	t.Run("executor handles out-of-order VaultDON responses correctly", func(t *testing.T) {
		// This test verifies that when VaultDON returns secrets in a different order
		// than they were requested, the executor correctly reorders them to match
		// the original request order before passing to the enclave.

		// The executor uses common.HexToAddress(workflowOwner).String() which converts
		// "test-owner" to the zero address
		expectedOwner := "0x0000000000000000000000000000000000000000"

		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			var getSecretsReq vault.GetSecretsRequest
			err := req.Payload.UnmarshalTo(&getSecretsReq)
			require.NoError(t, err)

			// Verify request has 3 secrets in order: secret-a, secret-b, secret-c
			require.Len(t, getSecretsReq.Requests, 3)
			assert.Equal(t, "secret-a", getSecretsReq.Requests[0].GetId().GetKey())
			assert.Equal(t, "secret-b", getSecretsReq.Requests[1].GetId().GetKey())
			assert.Equal(t, "secret-c", getSecretsReq.Requests[2].GetId().GetKey())

			// Return secrets in DIFFERENT order: secret-c, secret-a, secret-b
			vaultDONResponsePayload := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key:       "secret-c",
							Namespace: "test-ns",
							Owner:     expectedOwner,
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value_c")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share_c"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
					{
						Id: &vault.SecretIdentifier{
							Key:       "secret-a",
							Namespace: "test-ns",
							Owner:     expectedOwner,
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value_a")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share_a"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
					{
						Id: &vault.SecretIdentifier{
							Key:       "secret-b",
							Namespace: "test-ns",
							Owner:     expectedOwner,
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_value_b")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										Shares:        []string{hex.EncodeToString([]byte("share_b"))},
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
									},
								},
							},
						},
					},
				},
			}

			respAny, err := anypb.New(vaultDONResponsePayload)
			require.NoError(t, err)

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			require.Len(t, reqs, 1)
			req := reqs[0]

			// Verify ciphertexts and names are in the ORIGINAL request order (a, b, c)
			require.Len(t, req.CiphertextNames, 3)
			assert.Equal(t, "secret-a", req.CiphertextNames[0], "First ciphertext name should be secret-a")
			assert.Equal(t, "secret-b", req.CiphertextNames[1], "Second ciphertext name should be secret-b")
			assert.Equal(t, "secret-c", req.CiphertextNames[2], "Third ciphertext name should be secret-c")

			// Verify the ciphertext values match the correct secrets (reordered from vault response)
			require.Len(t, req.Ciphertexts, 3)
			assert.Equal(t, []byte("encrypted_value_a"), req.Ciphertexts[0], "First ciphertext should be value_a")
			assert.Equal(t, []byte("encrypted_value_b"), req.Ciphertexts[1], "Second ciphertext should be value_b")
			assert.Equal(t, []byte("encrypted_value_c"), req.Ciphertexts[2], "Third ciphertext should be value_c")

			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		// Create test input with 3 secrets in order: a, b, c
		testInput := &framework.TestInput{TestField: "test"}
		actionInput := &framework.TestActionInput{
			VaultDonSecrets: []*frameworktypes.SecretIdentifier{
				{Key: "secret-a", Namespace: "test-ns"},
				{Key: "secret-b", Namespace: "test-ns"},
				{Key: "secret-c", Namespace: "test-ns"},
			},
			Input: testInput,
		}

		executor := framework.NewTestExecutor(
			logger.Test(t),
			getMockKeystore(),
			mockEnclaveClient,
			mockVaultDON,
			NewMockMetrics(),
			getDefaultRateLimiter(),
			1,
			0,
			"test-capability-id",
			false, // disable secrets cache for this test
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)

		protoBytes, err := proto.Marshal(actionInput.GetInput())
		require.NoError(t, err)

		output, err := executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:          WORKFLOW_ID,
			WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
			WorkflowName:        WORKFLOW_NAME,
			WorkflowOwner:       WORKFLOW_OWNER,
		})
		assert.NoError(t, err)
		assert.NotNil(t, output)
	})
}

func TestExecutor_Execute_EmitsAttestationFallbackMetric(t *testing.T) {
	mockVaultDONCapability := &MockVaultDONCapability{}
	mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
		respAny, err := anypb.New(getValidGetSecretsResponse())
		require.NoError(t, err)
		return capabilities.CapabilityResponse{Payload: respAny}, nil
	}

	mockEnclaveClient := &MockEnclaveClient{}
	mockEnclaveClient.GetPublicKeysFunc = func(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error) {
		return []enclavetypes.EnclavePublicKeyData{{
			PublicKeyResponse: enclavetypes.PublicKeyResponse{
				PublicKeys:    [][]byte{[]byte("mock_public_key_bytes_1")},
				CreationTimes: []time.Time{time.Now()},
				TTLs:          []time.Duration{time.Hour},
				Config: enclavetypes.EnclaveConfig{
					Signers: [][]byte{mockPeerID1[:], mockPeerID2[:]},
				},
				Attestation: []byte("mock_attestation_data"),
			},
			EnclaveID:               mockEnclaveID,
			AttestationFallbackUsed: true,
		}}, nil
	}
	mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
		responses, err := mockEnclaveClient.commonExecuteBatchReturn(t)
		if err != nil {
			return nil, err
		}
		responses[0].AttestationFallbackUsed = true
		return responses, nil
	}

	mockVaultDON := framework.VaultDON{
		CryptographyThreshold: 1,
		Capability:            mockVaultDONCapability,
	}
	mockMetrics := NewMockMetrics()

	_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, mockMetrics, getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
	require.NoError(t, err)

	require.Contains(t, mockMetrics.EmitRecords, "attestation_validation_fallback_used")
	records := mockMetrics.EmitRecords["attestation_validation_fallback_used"]
	require.Len(t, records, 2)

	endpoints := map[string]bool{}
	for _, record := range records {
		endpoint, ok := record["endpoint"].(string)
		require.True(t, ok)
		endpoints[endpoint] = true
		assert.NotEmpty(t, record["enclave.id"])
	}
	assert.True(t, endpoints["publicKeys"])
	assert.True(t, endpoints["execute"])
}

func TestExecutor_ExecuteFailAfterRetry(t *testing.T) {
	t.Run("executor fails with error after retries", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		maxAllowedRetries := 3
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			if mockEnclaveClient.callCount < maxAllowedRetries {
				mockEnclaveClient.callCount++
				return nil, errors.New("simulated enclave client error")
			} else {
				assert.Fail(t, "Expected ExecuteBatch to be called 3 times before giving up")
			}
			if mockEnclaveClient.callCount >= maxAllowedRetries {
				assert.Fail(t, "Expected ExecuteBatch to be called 3 times before giving up")
				return nil, nil
			}
			mockEnclaveClient.callCount++
			return nil, errors.New("simulated enclave client error")
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		mockMetrics := NewMockMetrics()
		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, mockMetrics, getDefaultRateLimiter(), maxAllowedRetries, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("failed after 3 retries: failed to execute enclave request. enclave ID: %s, error: simulated enclave client error", base64.StdEncoding.EncodeToString(mockEnclaveID[:])))

		// On failure, execute_total is still emitted once: outcome=error with a
		// non-negative total duration, so failed-request latency is recorded.
		AssertCalledNTimes(t, mockMetrics, "execute_total", 1)
		require.Contains(t, mockMetrics.EmitRecords, "execute_total")
		assert.Equal(t, "error", mockMetrics.EmitRecords["execute_total"][0]["outcome"])
		assert.Equal(t, TEST_NODE_ID, mockMetrics.EmitRecords["execute_total"][0]["node.id"])
		assert.GreaterOrEqual(t, mockMetrics.EmitRecords["execute_total"][0]["duration_seconds"].(float64), 0.0)
		// requests_completed_total is success-only and must NOT fire on failure.
		AssertCalledNTimes(t, mockMetrics, "requests_completed_total", 0)
		// execute_error fired on each of the 3 attempts, each carrying a duration.
		require.Contains(t, mockMetrics.EmitRecords, "execute_error")
		assert.Contains(t, mockMetrics.EmitRecords["execute_error"][0], "duration_seconds")
	})
}

func TestExecutor_DifferentEnclaveOnRetry(t *testing.T) {
	t.Run("GetPublicKeys is called on each retry attempt", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}

		// Track request IDs passed to GetPublicKeys.
		var capturedRequestIDs [][32]byte
		mockEnclaveClient.GetPublicKeysFunc = func(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error) {
			capturedRequestIDs = append(capturedRequestIDs, requestID)
			return []enclavetypes.EnclavePublicKeyData{
				{
					PublicKeyResponse: enclavetypes.PublicKeyResponse{
						PublicKeys:    [][]byte{[]byte("mock_public_key_bytes_1")},
						CreationTimes: []time.Time{time.Now()},
						TTLs:          []time.Duration{time.Hour * 24},
						Config: enclavetypes.EnclaveConfig{
							Signers: [][]byte{mockPeerID1[:], mockPeerID2[:]},
						},
						Attestation: []byte("mock_attestation_data"),
					},
					EnclaveID: mockEnclaveID,
				},
			}, nil
		}

		maxAllowedRetries := 3
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			// Fail on first two attempts, succeed on third
			if mockEnclaveClient.callCount < 2 {
				mockEnclaveClient.callCount++
				return nil, errors.New("simulated enclave client error")
			}
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), maxAllowedRetries, 0)
		require.NoError(t, err)

		// Verify we captured calls from multiple retry attempts.
		require.GreaterOrEqual(t, len(capturedRequestIDs), 3, "Expected at least 3 GetPublicKeys calls (one per retry attempt)")

		// Verify request ID stays the same across retries (we no longer mutate it)
		for i := 1; i < len(capturedRequestIDs); i++ {
			assert.Equal(t, capturedRequestIDs[0], capturedRequestIDs[i], "Request ID should be the same across all retries")
		}
	})
}

func TestExecutor_ExecuteWithRateLimit(t *testing.T) {
	t.Run("executor fails due to rate limit being exceeded", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		rateLimiter, err := ratelimit.NewRateLimiter(ratelimit.RateLimiterConfig{
			GlobalRPS:      1,
			GlobalBurst:    1,
			PerSenderRPS:   1,
			PerSenderBurst: 1,
		})
		require.NoError(t, err)

		mockMetrics := NewMockMetrics()
		executor := framework.NewTestExecutor(
			logger.Test(t),
			getMockKeystore(),
			mockEnclaveClient,
			mockVaultDON,
			mockMetrics,
			rateLimiter,
			framework.DefaultMaxRetries,
			framework.DefaultRetryBackoffSeconds,
			"test-capability-id",
			true,
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)

		ctx := context.Background()
		workflow, removeWorkflow := testutils.NewWorkflow(ctx, testutils.WorkflowParams{
			T:     t,
			Owner: "owner1",
		})
		defer removeWorkflow(ctx)

		capInput := getTestExecutorInput()
		jsonEncodedProto, err := json.Marshal(capInput)
		require.NoError(t, err)

		_, err = executor.Execute(ctx, jsonEncodedProto, capInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:    workflow.ID,
			WorkflowOwner: workflow.Owner,
		})
		assert.NoError(t, err, "First request should not be rate limited")

		_, err = executor.Execute(ctx, jsonEncodedProto, capInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:    workflow.ID,
			WorkflowOwner: workflow.Owner,
		})
		assert.Error(t, err, "Second request should be rate limited")
		assert.Contains(t, err.Error(), "rate limit exceeded for workflow owner owner1", "Error message should indicate rate limiting")

		// Verify rate_limit_exceeded metric was emitted
		AssertCalledNTimes(t, mockMetrics, "rate_limit_exceeded", 1)
		require.Contains(t, mockMetrics.EmitRecords, "rate_limit_exceeded")
		assert.Equal(t, "owner1", mockMetrics.EmitRecords["rate_limit_exceeded"][0]["workflow.owner"])
		assert.Equal(t, TEST_NODE_ID, mockMetrics.EmitRecords["rate_limit_exceeded"][0]["node.id"])

		// execute_total fires on both calls: the first as success, the second
		// (rate-limited, before any enclave is selected) as error. The rate-limited
		// emission carries no enclave.id since none is known yet.
		AssertCalledNTimes(t, mockMetrics, "execute_total", 2)
		assert.Equal(t, "success", mockMetrics.EmitRecords["execute_total"][0]["outcome"])
		rateLimited := mockMetrics.EmitRecords["execute_total"][1]
		assert.Equal(t, "error", rateLimited["outcome"])
		assert.NotContains(t, rateLimited, "enclave.id", "rate-limited execute_total should omit enclave.id")
		assert.GreaterOrEqual(t, rateLimited["duration_seconds"].(float64), 0.0)
	})
}

func TestGetEnclaveNodes(t *testing.T) {
	t.Run("GetEnclaveNodes without API key", func(t *testing.T) {
		mockCapConfig := capabilities.CapabilityConfiguration{
			DefaultConfig: createMockEnclavesList(t, ""),
		}
		capConfig := framework.Config{}

		nodes, err := framework.GetEnclaveNodes(t.Context(), mockCapConfig, capConfig, "")
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		assert.Empty(t, nodes[0].EnclaveAuthHeader, "Expected no auth header when apiKey is empty")
	})

	t.Run("GetEnclaveNodes with API key", func(t *testing.T) {
		mockCapConfig := capabilities.CapabilityConfiguration{
			DefaultConfig: createMockEnclavesList(t, ""),
		}
		capConfig := framework.Config{}

		nodes, err := framework.GetEnclaveNodes(t.Context(), mockCapConfig, capConfig, "my-secret-api-key")
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		assert.Equal(t, "x-api-key: my-secret-api-key", nodes[0].EnclaveAuthHeader, "Expected auth header to be set correctly")
	})

	t.Run("GetEnclaveNodes with multiple enclaves", func(t *testing.T) {
		mockCapConfig := capabilities.CapabilityConfiguration{
			DefaultConfig: createMockEnclavesListMultiple(t, 3),
		}
		capConfig := framework.Config{}

		nodes, err := framework.GetEnclaveNodes(t.Context(), mockCapConfig, capConfig, "shared-api-key")
		require.NoError(t, err)
		require.Len(t, nodes, 3)

		for i, node := range nodes {
			assert.Equal(t, "x-api-key: shared-api-key", node.EnclaveAuthHeader,
				"Expected all enclaves to have the same auth header, failed at index %d", i)
		}
	})

	t.Run("GetEnclaveNodes with invalid enclave config type", func(t *testing.T) {
		// Create config with an unusual enclave type - UnwrapTo is lenient
		invalidConfig := enclavetypes.EnclavesList{
			Enclaves: []enclavetypes.Enclave{
				{
					EnclaveID:         [32]byte{1, 2, 3, 4, 5, 6, 7, 8},
					EnclaveURL:        "https://enclave1.example.com",
					EnclaveType:       "invalid-type-that-doesnt-exist",
					EnclaveAuthHeader: "",
					TrustedValues:     [][]byte{[]byte("{}")},
					Region:            "us-west-2",
				},
			},
		}
		wrappedInvalidConfig, err := values.WrapMap(invalidConfig)
		require.NoError(t, err)

		mockCapConfig := capabilities.CapabilityConfiguration{
			DefaultConfig: wrappedInvalidConfig,
		}
		capConfig := framework.Config{}

		// This should still succeed because UnwrapTo is lenient
		// The invalid type would only be caught during actual usage
		nodes, err := framework.GetEnclaveNodes(t.Context(), mockCapConfig, capConfig, "")
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		// Verify it parsed but has the invalid type
		assert.Equal(t, enclavetypes.EnclaveType("invalid-type-that-doesnt-exist"), nodes[0].EnclaveType)
	})
}

func TestExecutor_ExecuteWithSecretsCache(t *testing.T) {
	// common setup for cache tests
	baseMetadata := capabilities.RequestMetadata{
		WorkflowID:          WORKFLOW_ID,
		WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
		WorkflowName:        WORKFLOW_NAME,
		WorkflowOwner:       WORKFLOW_OWNER,
	}

	actionInput := getTestExecutorInput()
	protoBytes, err := proto.Marshal(actionInput.GetInput())
	require.NoError(t, err)

	// Mock EnclaveClient that returns "key1"
	mockEnclaveClientKey1 := &MockEnclaveClient{}
	mockEnclaveClientKey1.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
		return mockEnclaveClientKey1.commonExecuteBatchReturn(t)
	}
	mockEnclaveClientKey1.GetPublicKeysFunc = func(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error) {
		return []enclavetypes.EnclavePublicKeyData{
			{
				PublicKeyResponse: enclavetypes.PublicKeyResponse{
					PublicKeys: [][]byte{
						[]byte("mock_public_key_bytes_1"), // This key is part of the cache key
					},
					CreationTimes: []time.Time{time.Now()},
					TTLs:          []time.Duration{time.Hour * 24},
					Config: enclavetypes.EnclaveConfig{
						Signers: [][]byte{mockPeerID1[:], mockPeerID2[:]},
					},
					Attestation: []byte("mock_attestation_data"),
				},
				EnclaveID: mockEnclaveID,
			},
		}, nil
	}

	// Mock EnclaveClient that returns "key2"
	mockEnclaveClientKey2 := &MockEnclaveClient{}
	mockEnclaveClientKey2.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
		return mockEnclaveClientKey2.commonExecuteBatchReturn(t)
	}
	mockEnclaveClientKey2.GetPublicKeysFunc = func(ctx context.Context, requestID [32]byte, checkRequirements enclavetypes.RequirementsChecker) ([]enclavetypes.EnclavePublicKeyData, error) {
		return []enclavetypes.EnclavePublicKeyData{
			{
				PublicKeyResponse: enclavetypes.PublicKeyResponse{
					PublicKeys: [][]byte{
						[]byte("mock_public_key_bytes_2"), // A different key
					},
					CreationTimes: []time.Time{time.Now()},
					TTLs:          []time.Duration{time.Hour * 24},
					Config: enclavetypes.EnclaveConfig{
						Signers: [][]byte{mockPeerID1[:], mockPeerID2[:]},
					},
					Attestation: []byte("mock_attestation_data"),
				},
				EnclaveID: mockEnclaveID,
			},
		}, nil
	}

	t.Run("cache disabled", func(t *testing.T) {
		vaultDONCalls := 0
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONCalls++
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}
		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}
		mockMetrics := NewMockMetrics()

		executor := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClientKey1, mockVaultDON, mockMetrics,
			getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds, "test-capability-id",
			false, // enableSecretsCache = false
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)

		// Call 1
		_, err := executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 1, vaultDONCalls, "VaultDON should be called the first time")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 0)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 0) // Miss is only tracked if cache is enabled

		// Call 2 (same inputs)
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 2, vaultDONCalls, "VaultDON should be called again, cache is disabled")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 0)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 0)
	})

	t.Run("cache enabled - hit and miss", func(t *testing.T) {
		vaultDONCalls := 0
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONCalls++
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}
		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}
		mockMetrics := NewMockMetrics()

		executor := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClientKey1, mockVaultDON, mockMetrics,
			getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds, "test-capability-id",
			true, // enableSecretsCache = true
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)
		// Limits are re-resolved on every Execute, so enable the secrets cache via
		// the limits framework (the production source of truth).
		executor.SetLimitsFactoryForTesting(limits.Factory{Settings: staticSettings{value: "true"}})

		// Call 1 (Cache Miss)
		_, err := executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 1, vaultDONCalls, "VaultDON should be called the first time")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 1)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 0)

		// Call 2 (Cache Hit - same inputs)
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 1, vaultDONCalls, "VaultDON should NOT be called again, result should come from cache")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 1)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 1)
	})

	t.Run("cache enabled - key uniqueness", func(t *testing.T) {
		vaultDONCalls := 0
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			vaultDONCalls++
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}
		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}
		mockMetrics := NewMockMetrics()

		// We will swap the enclave client on the executor to test the public key part of the cache key
		executor := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClientKey1, mockVaultDON, mockMetrics,
			getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds, "test-capability-id",
			true, // enableSecretsCache = true
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)
		// Limits are re-resolved on every Execute, so enable the secrets cache via
		// the limits framework (the production source of truth).
		executor.SetLimitsFactoryForTesting(limits.Factory{Settings: staticSettings{value: "true"}})

		// Call 1 (Miss - owner1, key1)
		_, err := executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 1, vaultDONCalls, "VaultDON should be called")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 1)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 0)

		// Call 2 (Hit - owner1, key1)
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 1, vaultDONCalls, "VaultDON should not be called")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 1)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 1)

		// Call 3 (Miss - different owner)
		metadataOwner2 := baseMetadata
		metadataOwner2.WorkflowOwner = "different-owner"
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), metadataOwner2)
		require.NoError(t, err)
		assert.Equal(t, 2, vaultDONCalls, "VaultDON should be called again for different owner")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 2)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 1)

		// Call 4 (Miss - different enclave public key)

		// Re-create executor with key2
		executorKey2 := framework.NewTestExecutor(
			logger.Test(t), getMockKeystore(), mockEnclaveClientKey2, mockVaultDON, mockMetrics,
			getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds, "test-capability-id",
			true, // enableSecretsCache = true
			TEST_NODE_ID,
			getMockCapabilitiesRegistry(t, mockVaultDON),
		)
		// Limits are re-resolved on every Execute, so enable the secrets cache via
		// the limits framework (the production source of truth).
		executorKey2.SetLimitsFactoryForTesting(limits.Factory{Settings: staticSettings{value: "true"}})

		// Call 5 (Miss - owner1, key2)
		_, err = executorKey2.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 3, vaultDONCalls, "VaultDON should be called for different enclave public key")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 3)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 1)

		// Call 6 (Hit - owner1, key2)
		_, err = executorKey2.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), baseMetadata)
		require.NoError(t, err)
		assert.Equal(t, 3, vaultDONCalls, "VaultDON should not be called")
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_miss", 3)
		AssertCalledNTimes(t, mockMetrics, "vault_don_cache_hit", 2)
	})
}

func TestEnsureFreshEnclaves_ConfigurationChange(t *testing.T) {
	t.Run("UpdateNodes is called with new enclaves when registry configuration changes", func(t *testing.T) {
		// Track what nodes are passed to UpdateNodes
		var updateNodesCallCount int
		var lastUpdatedNodes []enclavetypes.Enclave

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}
		mockEnclaveClient.UpdateNodesFunc = func(nodes []enclavetypes.Enclave) {
			updateNodesCallCount++
			lastUpdatedNodes = nodes
		}

		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}
		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}

		// Create a mutable configuration that we can change between calls
		currentEnclaveID := [32]byte{1, 1, 1, 1, 1, 1, 1, 1}
		currentEnclaveURL := "https://enclave-v1.example.com"

		mockRegistry := &MockCapabilitiesRegistry{
			LocalNodeFunc: func(ctx context.Context) (capabilities.Node, error) {
				return capabilities.Node{
					WorkflowDON: capabilities.DON{ID: 1, F: 0, Members: []p2ptypes.PeerID{mockPeerID1, mockPeerID2}},
					PeerID:      nil,
				}, nil
			},
			ConfigForCapabilityFunc: func(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error) {
				// Return whatever the current configuration is
				enclavesList := enclavetypes.EnclavesList{
					Enclaves: []enclavetypes.Enclave{
						{
							EnclaveID:     currentEnclaveID,
							EnclaveURL:    currentEnclaveURL,
							EnclaveType:   "nitro",
							TrustedValues: [][]byte{[]byte("{}")},
							Region:        "us-west-2",
						},
					},
				}
				wrappedConfig, err := values.WrapMap(enclavesList)
				require.NoError(t, err)
				return capabilities.CapabilityConfiguration{DefaultConfig: wrappedConfig}, nil
			},
			GetExecutableFunc: func(ctx context.Context, ID string) (capabilities.ExecutableCapability, error) {
				if ID == vault.CapabilityID {
					return mockVaultDONCapability, nil
				}
				return nil, fmt.Errorf("unknown capability ID: %s", ID)
			},
		}

		executor := framework.NewTestExecutor(
			logger.Test(t),
			getMockKeystore(),
			mockEnclaveClient,
			mockVaultDON,
			NewMockMetrics(),
			getDefaultRateLimiter(),
			1, // maxRetries
			0, // retryBackoffSeconds
			"test-capability-id",
			false, // disable secrets cache
			TEST_NODE_ID,
			mockRegistry,
		)

		actionInput := getTestExecutorInput()
		protoBytes, err := proto.Marshal(actionInput.GetInput())
		require.NoError(t, err)

		metadata := capabilities.RequestMetadata{
			WorkflowID:          WORKFLOW_ID,
			WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
			WorkflowName:        WORKFLOW_NAME,
			WorkflowOwner:       WORKFLOW_OWNER,
		}

		// First execution - should call UpdateNodes with initial config
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), metadata)
		require.NoError(t, err)

		assert.Equal(t, 1, updateNodesCallCount, "UpdateNodes should be called once after first execution")
		require.Len(t, lastUpdatedNodes, 1, "Should have 1 enclave node")
		assert.Equal(t, currentEnclaveID, lastUpdatedNodes[0].EnclaveID, "First call should have initial enclave ID")
		assert.Equal(t, "https://enclave-v1.example.com", lastUpdatedNodes[0].EnclaveURL, "First call should have initial URL")

		// Change the configuration (simulating registry update)
		currentEnclaveID = [32]byte{2, 2, 2, 2, 2, 2, 2, 2}
		currentEnclaveURL = "https://enclave-v2.example.com"

		// Second execution with different execution ID to avoid caching
		metadata.WorkflowExecutionID = "test-workflow-execution-id-2"
		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), metadata)
		require.NoError(t, err)

		assert.Equal(t, 2, updateNodesCallCount, "UpdateNodes should be called again after second execution")
		require.Len(t, lastUpdatedNodes, 1, "Should have 1 enclave node")
		assert.Equal(t, currentEnclaveID, lastUpdatedNodes[0].EnclaveID, "Second call should have new enclave ID")
		assert.Equal(t, "https://enclave-v2.example.com", lastUpdatedNodes[0].EnclaveURL, "Second call should have new URL")
	})

	t.Run("UpdateNodes receives multiple enclaves when configuration has multiple", func(t *testing.T) {
		var lastUpdatedNodes []enclavetypes.Enclave

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}
		mockEnclaveClient.UpdateNodesFunc = func(nodes []enclavetypes.Enclave) {
			lastUpdatedNodes = nodes
		}

		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, _ := anypb.New(getValidGetSecretsResponse())
			return capabilities.CapabilityResponse{Payload: respAny}, nil
		}
		mockVaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: mockVaultDONCapability}

		mockRegistry := &MockCapabilitiesRegistry{
			LocalNodeFunc: func(ctx context.Context) (capabilities.Node, error) {
				return capabilities.Node{
					WorkflowDON: capabilities.DON{ID: 1, F: 0, Members: []p2ptypes.PeerID{mockPeerID1, mockPeerID2}},
					PeerID:      nil,
				}, nil
			},
			ConfigForCapabilityFunc: func(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error) {
				// Return multiple enclaves
				enclavesList := enclavetypes.EnclavesList{
					Enclaves: []enclavetypes.Enclave{
						{
							EnclaveID:     [32]byte{1, 0, 0, 0, 0, 0, 0, 0},
							EnclaveURL:    "https://enclave-1.example.com",
							EnclaveType:   "nitro",
							TrustedValues: [][]byte{[]byte("{}")},
							Region:        "us-west-2",
						},
						{
							EnclaveID:     [32]byte{2, 0, 0, 0, 0, 0, 0, 0},
							EnclaveURL:    "https://enclave-2.example.com",
							EnclaveType:   "nitro",
							TrustedValues: [][]byte{[]byte("{}")},
							Region:        "us-west-2",
						},
						{
							EnclaveID:     [32]byte{3, 0, 0, 0, 0, 0, 0, 0},
							EnclaveURL:    "https://enclave-3.example.com",
							EnclaveType:   "nitro",
							TrustedValues: [][]byte{[]byte("{}")},
							Region:        "us-west-2",
						},
					},
				}
				wrappedConfig, err := values.WrapMap(enclavesList)
				require.NoError(t, err)
				return capabilities.CapabilityConfiguration{DefaultConfig: wrappedConfig}, nil
			},
			GetExecutableFunc: func(ctx context.Context, ID string) (capabilities.ExecutableCapability, error) {
				if ID == vault.CapabilityID {
					return mockVaultDONCapability, nil
				}
				return nil, fmt.Errorf("unknown capability ID: %s", ID)
			},
		}

		executor := framework.NewTestExecutor(
			logger.Test(t),
			getMockKeystore(),
			mockEnclaveClient,
			mockVaultDON,
			NewMockMetrics(),
			getDefaultRateLimiter(),
			1,
			0,
			"test-capability-id",
			false,
			TEST_NODE_ID,
			mockRegistry,
		)

		actionInput := getTestExecutorInput()
		protoBytes, err := proto.Marshal(actionInput.GetInput())
		require.NoError(t, err)

		_, err = executor.Execute(context.Background(), protoBytes, actionInput.GetVaultDonSecrets(), capabilities.RequestMetadata{
			WorkflowID:          WORKFLOW_ID,
			WorkflowExecutionID: WORKFLOW_EXECUTION_ID,
			WorkflowName:        WORKFLOW_NAME,
			WorkflowOwner:       WORKFLOW_OWNER,
		})
		require.NoError(t, err)

		require.Len(t, lastUpdatedNodes, 3, "Should have 3 enclave nodes from configuration")
		assert.Equal(t, "https://enclave-3.example.com", lastUpdatedNodes[0].EnclaveURL)
		assert.Equal(t, "https://enclave-2.example.com", lastUpdatedNodes[1].EnclaveURL)
		assert.Equal(t, "https://enclave-1.example.com", lastUpdatedNodes[2].EnclaveURL)
	})
}

// proposalTestEnclaveConfig is the master key / threshold the enclave reports;
// only the signer set and F change during a membership rotation.
var (
	proposalMasterPublicKey = []byte("master-public-key")
	proposalT               = uint32(2)
)

// newProposalExecutor builds an executor wired for testing the config-update
// proposal path. localNode is read both at construction (seeding the baseline DON
// membership) and on each EnsureFreshEnclaves call, so mutating what it returns
// simulates a DON membership change.
func newProposalExecutor(t *testing.T, ks core.Keystore, mc *MockEnclaveClient, localNode func() capabilities.Node) (*framework.RealExecutor, *MockMetrics) {
	metrics := NewMockMetrics()
	vaultCap := &MockVaultDONCapability{}
	vaultDON := framework.VaultDON{CryptographyThreshold: 1, Capability: vaultCap}
	reg := &MockCapabilitiesRegistry{
		LocalNodeFunc: func(ctx context.Context) (capabilities.Node, error) { return localNode(), nil },
		ConfigForCapabilityFunc: func(ctx context.Context, capabilityID string, donID uint32) (capabilities.CapabilityConfiguration, error) {
			wrapped, err := values.WrapMap(enclavetypes.EnclavesList{Enclaves: []enclavetypes.Enclave{{
				EnclaveID:     mockEnclaveID,
				EnclaveURL:    "https://mock-enclave.example.com",
				EnclaveType:   "nitro",
				TrustedValues: [][]byte{[]byte("{}")},
				Region:        "us-west-2",
			}}})
			require.NoError(t, err)
			return capabilities.CapabilityConfiguration{DefaultConfig: wrapped}, nil
		},
		GetExecutableFunc: func(ctx context.Context, ID string) (capabilities.ExecutableCapability, error) {
			if ID == vault.CapabilityID {
				return vaultCap, nil
			}
			return nil, fmt.Errorf("unknown capability ID: %s", ID)
		},
	}
	exec := framework.NewTestExecutor(logger.Test(t), ks, mc, vaultDON, metrics, getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID, reg)
	return exec, metrics
}

func nodeWith(members []p2ptypes.PeerID, f uint8) capabilities.Node {
	return capabilities.Node{WorkflowDON: capabilities.DON{ID: 1, F: f, Members: members}}
}

// enclaveConfigsWith returns a single-enclave GetConfigs response carrying the given config.
func enclaveConfigsWith(signers [][]byte, f uint32) []enclavetypes.EnclaveConfig {
	return []enclavetypes.EnclaveConfig{{Signers: signers, MasterPublicKey: proposalMasterPublicKey, T: proposalT, F: f}}
}

func sortedMembers(members ...p2ptypes.PeerID) [][]byte {
	out := make([][]byte, len(members))
	for i, m := range members {
		b := make([]byte, len(m))
		copy(b, m[:])
		out[i] = b
	}
	slices.SortFunc(out, bytes.Compare)
	return out
}

func TestEnsureFreshEnclaves_ConfigUpdateProposal(t *testing.T) {
	t.Run("no proposal when membership is unchanged", func(t *testing.T) {
		var updateCalls int
		mc := &MockEnclaveClient{
			UpdateConfigFunc: func(ctx context.Context, _ enclavetypes.UpdateConfigRequest) error { updateCalls++; return nil },
		}
		exec, _ := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node {
			return nodeWith([]p2ptypes.PeerID{mockPeerID1, mockPeerID2}, 0)
		})

		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 0, updateCalls, "unchanged membership must not trigger a config update")
	})

	t.Run("proposes correctly signed config when membership changes", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		var signedMsg []byte
		ks := &mockKeystore{
			accounts: []string{core.StandardCapabilityAccount},
			signFunc: func(ctx context.Context, account string, msg []byte) ([]byte, error) {
				signedMsg = msg
				return []byte("test-sig"), nil
			},
		}

		var gotUpdate enclavetypes.UpdateConfigRequest
		var updateCalls int
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				return enclaveConfigsWith(sortedMembers(mockPeerID1, mockPeerID2), 0), nil
			},
			UpdateConfigFunc: func(ctx context.Context, u enclavetypes.UpdateConfigRequest) error {
				updateCalls++
				gotUpdate = u
				return nil
			},
		}
		exec, metrics := newProposalExecutor(t, ks, mc, func() capabilities.Node { return nodeWith(members, 0) })

		// Rotate a third node into the DON.
		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))

		require.Equal(t, 1, updateCalls, "membership change must trigger exactly one config update")

		var proposed enclavetypes.EnclaveConfig
		require.NoError(t, json.Unmarshal(gotUpdate.Config, &proposed))
		assert.Equal(t, sortedMembers(mockPeerID1, mockPeerID2, mockPeerID3), proposed.Signers)
		assert.Equal(t, uint32(0), proposed.F)
		assert.Equal(t, proposalMasterPublicKey, proposed.MasterPublicKey, "master key carried over from current enclave config")
		assert.Equal(t, proposalT, proposed.T, "threshold carried over from current enclave config")

		// The vote must be signed over the config-update domain-separated hash of the proposed config.
		proposedHash := proposed.Hash()
		expectedMsg := enclavetypes.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputeConfigUpdatePrefix(), proposedHash[:])
		assert.Equal(t, expectedMsg, signedMsg)
		assert.Equal(t, []byte("test-sig"), gotUpdate.Signature)

		AssertCalledNTimes(t, metrics, "config_update_proposed", 1)
		AssertCalledNTimes(t, metrics, "config_update_proposal_failed", 0)
	})

	t.Run("skips proposal and advances baseline once enclave already reports new membership", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		var getCalls, updateCalls int
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				getCalls++
				// Enclave already serves the new (rotated) signer set.
				return enclaveConfigsWith(sortedMembers(mockPeerID1, mockPeerID2, mockPeerID3), 0), nil
			},
			UpdateConfigFunc: func(ctx context.Context, _ enclavetypes.UpdateConfigRequest) error { updateCalls++; return nil },
		}
		exec, _ := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node { return nodeWith(members, 0) })

		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 0, updateCalls, "no vote needed when enclave already matches")
		assert.Equal(t, 1, getCalls)

		// Baseline should now be advanced: a second refresh detects no change and does not even read public keys.
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 0, updateCalls)
		assert.Equal(t, 1, getCalls, "baseline advanced, so no further proposal work")
	})

	t.Run("does not advance baseline on failure, retries on next refresh", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		fail := true
		var updateCalls int
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				if fail {
					return nil, errors.New("enclaves unreachable")
				}
				return enclaveConfigsWith(sortedMembers(mockPeerID1, mockPeerID2), 0), nil
			},
			UpdateConfigFunc: func(ctx context.Context, _ enclavetypes.UpdateConfigRequest) error { updateCalls++; return nil },
		}
		exec, metrics := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node { return nodeWith(members, 0) })

		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 0, updateCalls, "failed fetch must not broadcast a vote")
		AssertCalledNTimes(t, metrics, "config_update_proposal_failed", 1)

		// Recovery: baseline was not advanced, so the next refresh retries and succeeds.
		fail = false
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 1, updateCalls, "proposal retried after the transient failure")
	})

	t.Run("fails when enclaves report inconsistent master key", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		var updateCalls int
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				return []enclavetypes.EnclaveConfig{
					{Signers: sortedMembers(mockPeerID1, mockPeerID2, mockPeerID3), MasterPublicKey: []byte("mpk-a"), T: proposalT},
					{Signers: sortedMembers(mockPeerID1, mockPeerID2, mockPeerID3), MasterPublicKey: []byte("mpk-b"), T: proposalT},
				}, nil
			},
			UpdateConfigFunc: func(ctx context.Context, _ enclavetypes.UpdateConfigRequest) error { updateCalls++; return nil },
		}
		exec, metrics := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node { return nodeWith(members, 0) })

		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		assert.Equal(t, 0, updateCalls)
		AssertCalledNTimes(t, metrics, "config_update_proposal_failed", 1)
	})

	t.Run("fails when no enclave configs are available", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				return nil, nil
			},
		}
		exec, metrics := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node { return nodeWith(members, 0) })

		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		AssertCalledNTimes(t, metrics, "config_update_proposal_failed", 1)
	})

	t.Run("reports failure when the vote broadcast errors", func(t *testing.T) {
		members := []p2ptypes.PeerID{mockPeerID1, mockPeerID2}
		mc := &MockEnclaveClient{
			GetConfigsFunc: func(ctx context.Context) ([]enclavetypes.EnclaveConfig, error) {
				return enclaveConfigsWith(sortedMembers(mockPeerID1, mockPeerID2), 0), nil
			},
			UpdateConfigFunc: func(ctx context.Context, _ enclavetypes.UpdateConfigRequest) error {
				return errors.New("all enclaves unreachable")
			},
		}
		exec, metrics := newProposalExecutor(t, getMockKeystore(), mc, func() capabilities.Node { return nodeWith(members, 0) })

		members = []p2ptypes.PeerID{mockPeerID1, mockPeerID2, mockPeerID3}
		require.NoError(t, exec.EnsureFreshEnclaves(context.Background()))
		AssertCalledNTimes(t, metrics, "config_update_proposed", 0)
		AssertCalledNTimes(t, metrics, "config_update_proposal_failed", 1)
	})
}

// Helper functions for creating mock configurations
func createMockEnclavesList(t *testing.T, authHeader string) *values.Map {
	enclavesList := enclavetypes.EnclavesList{
		Enclaves: []enclavetypes.Enclave{
			{
				EnclaveID:         [32]byte{1, 2, 3, 4, 5, 6, 7, 8},
				EnclaveURL:        "https://enclave1.example.com",
				EnclaveType:       "nitro",
				EnclaveAuthHeader: authHeader,
				TrustedValues:     [][]byte{[]byte("{}")},
				Region:            "us-west-2",
			},
		},
	}
	wrappedConfig, err := values.WrapMap(enclavesList)
	require.NoError(t, err)
	return wrappedConfig
}

func createMockEnclavesListMultiple(t *testing.T, count int) *values.Map {
	enclaves := make([]enclavetypes.Enclave, count)
	for i := 0; i < count; i++ {
		enclaves[i] = enclavetypes.Enclave{
			EnclaveID:         [32]byte{byte(i + 1)},
			EnclaveURL:        "https://enclave.example.com",
			EnclaveType:       "nitro",
			EnclaveAuthHeader: "",
			TrustedValues:     [][]byte{[]byte("{}")},
			Region:            "us-west-2",
		}
	}
	enclavesList := enclavetypes.EnclavesList{
		Enclaves: enclaves,
	}
	wrappedConfig, err := values.WrapMap(enclavesList)
	require.NoError(t, err)
	return wrappedConfig
}

func TestExecutor_ExecuteWithBinaryShares(t *testing.T) {
	t.Run("executor decodes binary-encoded decryption shares", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, err := anypb.New(getValidGetSecretsResponseWithBinaryShares())
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			assert.Equal(t, 1, len(reqs), "Expected one signed compute request")
			assert.Equal(t, 1, len(reqs[0].Ciphertexts), "Expected one ciphertext in the request")
			assert.Equal(t, 1, len(reqs[0].EncryptedDecryptionKeyShares), "Expected 1 set of shares in the request")
			assert.Equal(t, 2, len(reqs[0].EncryptedDecryptionKeyShares[0]), "Expected 2 shares per ciphertext")
			// Verify shares are the binary values (not hex-encoded)
			assert.Equal(t, []byte("share1_for_my-secret-id"), reqs[0].EncryptedDecryptionKeyShares[0][0], "Expected first share to match binary value")
			assert.Equal(t, []byte("share2_for_my-secret-id"), reqs[0].EncryptedDecryptionKeyShares[0][1], "Expected second share to match binary value")

			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		executeOutput, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.NoError(t, err)
		assert.NotNil(t, executeOutput, "Expected non-nil output from executor")

		var testOutput framework.TestOutput
		err = json.Unmarshal(executeOutput, &testOutput)
		assert.NoError(t, err)
		AssertBasicOutputValid(t, &testOutput)
	})
}

func TestExecutor_ExecuteWithHexSharesFallback(t *testing.T) {
	t.Run("executor falls back to hex-decoding when binary shares are absent", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			respAny, err := anypb.New(getValidGetSecretsResponse())
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}
		mockEnclaveClient.ExecuteBatchFunc = func(ctx context.Context, reqs []enclavetypes.SignedComputeRequest, enclaveIDs [][32]byte) ([]enclavetypes.ExecuteResponse, error) {
			assert.Equal(t, 1, len(reqs), "Expected one signed compute request")
			assert.Equal(t, 1, len(reqs[0].Ciphertexts), "Expected one ciphertext in the request")
			assert.Equal(t, 1, len(reqs[0].EncryptedDecryptionKeyShares), "Expected 1 set of shares in the request")
			assert.Equal(t, 2, len(reqs[0].EncryptedDecryptionKeyShares[0]), "Expected 2 shares per ciphertext")
			// Verify shares were decoded from hex
			assert.Equal(t, []byte("share1_for_my-secret-id"), reqs[0].EncryptedDecryptionKeyShares[0][0], "Expected first share to be hex-decoded correctly")
			assert.Equal(t, []byte("share2_for_my-secret-id"), reqs[0].EncryptedDecryptionKeyShares[0][1], "Expected second share to be hex-decoded correctly")

			return mockEnclaveClient.commonExecuteBatchReturn(t)
		}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		executeOutput, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.NoError(t, err)
		assert.NotNil(t, executeOutput, "Expected non-nil output from executor")

		var testOutput framework.TestOutput
		err = json.Unmarshal(executeOutput, &testOutput)
		assert.NoError(t, err)
		AssertBasicOutputValid(t, &testOutput)
	})
}

func TestExecutor_ExecuteWithNoSharesError(t *testing.T) {
	t.Run("executor returns error when neither binary nor hex shares are present", func(t *testing.T) {
		mockVaultDONCapability := &MockVaultDONCapability{}
		mockVaultDONCapability.ExecuteFunc = func(ctx context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
			// Return response with empty shares
			emptySharesResponse := &vault.GetSecretsResponse{
				Responses: []*vault.SecretResponse{
					{
						Id: &vault.SecretIdentifier{
							Key:       "my-secret-api-key",
							Namespace: "my-namespace",
							Owner:     "0x0000000000000000000000000000000000000000",
						},
						Result: &vault.SecretResponse_Data{
							Data: &vault.SecretData{
								EncryptedValue: hex.EncodeToString([]byte("encrypted_secret_data_for_my-secret-id")),
								EncryptedDecryptionKeyShares: []*vault.EncryptedShares{
									{
										EncryptionKey: string([]byte("mock_public_key_bytes_1")),
										// Both Shares and BinaryShares are empty
									},
								},
							},
						},
					},
				},
			}

			respAny, err := anypb.New(emptySharesResponse)
			require.NoError(t, err, "Failed to marshal VaultDON response payload to Any")

			return capabilities.CapabilityResponse{
				Payload: respAny,
			}, nil
		}

		mockEnclaveClient := &MockEnclaveClient{}

		mockVaultDON := framework.VaultDON{
			CryptographyThreshold: 1,
			Capability:            mockVaultDONCapability,
		}

		_, err := setupAndExecuteExecutor(t, mockEnclaveClient, mockVaultDON, NewMockMetrics(), getDefaultRateLimiter(), framework.DefaultMaxRetries, framework.DefaultRetryBackoffSeconds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no decryption shares found for secret my-secret-api-key: neither binary nor hex-encoded shares present")
	})
}

func TestParseConfig(t *testing.T) {
	t.Run("empty JSON uses all defaults", func(t *testing.T) {
		parsed, err := framework.ParseConfig("{}")
		require.NoError(t, err)

		assert.Equal(t, framework.DefaultMaxRetries, parsed.MaxRetries)
		assert.Equal(t, framework.DefaultRetryBackoffSeconds, parsed.RetryBackoffSeconds)
		assert.Equal(t, float64(framework.DefaultGlobalRPS), parsed.GlobalRPS)
		assert.Equal(t, framework.DefaultGlobalBurst, parsed.GlobalBurst)
		assert.Equal(t, float64(framework.DefaultWorkflowOwnerRPS), parsed.WorkflowOwnerRPS)
		assert.Equal(t, framework.DefaultWorkflowOwnerBurst, parsed.WorkflowOwnerBurst)
		assert.Equal(t, enclavetypes.DefaultEnableSecretsCache, parsed.EnableSecretsCache)
		assert.Equal(t, enclavetypes.DefaultEnclaveRequestTimeout, parsed.EnclaveRequestTimeout)

		// Cache defaults
		assert.Equal(t, enclaveclient.DefaultCacheConfig, parsed.CacheConfig)

		// Session defaults
		assert.Equal(t, enclaveclient.DefaultSessionConfig, parsed.SessionConfig)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		_, err := framework.ParseConfig("not-json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal config")
	})

	t.Run("partial cache config overrides only specified fields", func(t *testing.T) {
		configJSON := `{
			"EnableCache": false,
			"CacheTTLSeconds": 120,
			"CacheMaxTTLSeconds": 600
		}`
		parsed, err := framework.ParseConfig(configJSON)
		require.NoError(t, err)

		assert.False(t, parsed.CacheConfig.EnableCache)
		assert.Equal(t, 120*time.Second, parsed.CacheConfig.DefaultTTL)
		assert.Equal(t, 600*time.Second, parsed.CacheConfig.MaxTTL)
		// Unset fields keep defaults
		assert.Equal(t, enclaveclient.DefaultCacheConfig.CleanupInterval, parsed.CacheConfig.CleanupInterval)
		assert.Equal(t, enclaveclient.DefaultCacheConfig.TTLBufferPercent, parsed.CacheConfig.TTLBufferPercent)
		assert.Equal(t, enclaveclient.DefaultCacheConfig.EnableProactiveRefresh, parsed.CacheConfig.EnableProactiveRefresh)
		assert.Equal(t, enclaveclient.DefaultCacheConfig.RefreshIntervalPercent, parsed.CacheConfig.RefreshIntervalPercent)
		assert.Equal(t, enclaveclient.DefaultCacheConfig.MinRefreshInterval, parsed.CacheConfig.MinRefreshInterval)
		assert.Equal(t, enclaveclient.DefaultCacheConfig.RefreshTimeout, parsed.CacheConfig.RefreshTimeout)
	})

	t.Run("all cache config fields can be overridden", func(t *testing.T) {
		configJSON := `{
			"EnableCache": false,
			"CacheTTLSeconds": 60,
			"CacheMaxTTLSeconds": 300,
			"CacheCleanupSeconds": 120,
			"CacheTTLBufferPercent": 0.2,
			"EnableProactiveRefresh": false,
			"RefreshIntervalPercent": 0.5,
			"MinRefreshIntervalSeconds": 10,
			"RefreshTimeoutSeconds": 15
		}`
		parsed, err := framework.ParseConfig(configJSON)
		require.NoError(t, err)

		assert.False(t, parsed.CacheConfig.EnableCache)
		assert.Equal(t, 60*time.Second, parsed.CacheConfig.DefaultTTL)
		assert.Equal(t, 300*time.Second, parsed.CacheConfig.MaxTTL)
		assert.Equal(t, 120*time.Second, parsed.CacheConfig.CleanupInterval)
		assert.InDelta(t, 0.2, parsed.CacheConfig.TTLBufferPercent, 0.001)
		assert.False(t, parsed.CacheConfig.EnableProactiveRefresh)
		assert.InDelta(t, 0.5, parsed.CacheConfig.RefreshIntervalPercent, 0.001)
		assert.Equal(t, 10*time.Second, parsed.CacheConfig.MinRefreshInterval)
		assert.Equal(t, 15*time.Second, parsed.CacheConfig.RefreshTimeout)
	})

	t.Run("session config overrides", func(t *testing.T) {
		configJSON := `{
			"EnableSessionPersistence": false,
			"SessionHeaderName": "X-Custom-Session"
		}`
		parsed, err := framework.ParseConfig(configJSON)
		require.NoError(t, err)

		assert.False(t, parsed.SessionConfig.EnableSessionPersistence)
		assert.Equal(t, "X-Custom-Session", parsed.SessionConfig.SessionHeaderName)
	})

	t.Run("enclave request timeout override", func(t *testing.T) {
		configJSON := `{"EnclaveRequestTimeoutSeconds": 30}`
		parsed, err := framework.ParseConfig(configJSON)
		require.NoError(t, err)

		assert.Equal(t, 30*time.Second, parsed.EnclaveRequestTimeout)
	})

	t.Run("all scalar overrides", func(t *testing.T) {
		configJSON := `{
			"MaxRetries": 5,
			"RetryBackoffSeconds": 10,
			"WorkflowOwnerRPS": 500.0,
			"WorkflowOwnerBurst": 250,
			"GlobalRPS": 2000.0,
			"GlobalBurst": 3000,
			"EnableSecretsCache": true,
			"EnclaveRequestTimeoutSeconds": 20
		}`
		parsed, err := framework.ParseConfig(configJSON)
		require.NoError(t, err)

		assert.Equal(t, 5, parsed.MaxRetries)
		assert.Equal(t, 10, parsed.RetryBackoffSeconds)
		assert.Equal(t, 500.0, parsed.WorkflowOwnerRPS)
		assert.Equal(t, 250, parsed.WorkflowOwnerBurst)
		assert.Equal(t, 2000.0, parsed.GlobalRPS)
		assert.Equal(t, 3000, parsed.GlobalBurst)
		assert.True(t, parsed.EnableSecretsCache)
		assert.Equal(t, 20*time.Second, parsed.EnclaveRequestTimeout)
	})
}
