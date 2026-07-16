package framework

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/confidential-compute/types"
)

// stubEnclaveClient is a minimal EnclaveClient for internal-package tests.
type stubEnclaveClient struct {
	getPublicKeysCalls int
	getPublicKeys      func(ctx context.Context, requestID [32]byte, checker types.RequirementsChecker) ([]types.EnclavePublicKeyData, error)
}

func (s *stubEnclaveClient) GetPublicKeys(ctx context.Context, requestID [32]byte, checker types.RequirementsChecker) ([]types.EnclavePublicKeyData, error) {
	s.getPublicKeysCalls++
	if s.getPublicKeys != nil {
		return s.getPublicKeys(ctx, requestID, checker)
	}
	return nil, nil
}

func (s *stubEnclaveClient) ExecuteBatch(context.Context, []types.SignedComputeRequest, [][32]byte) ([]types.ExecuteResponse, error) {
	return nil, nil
}
func (s *stubEnclaveClient) UpdateNodes([]types.Enclave) {}
func (s *stubEnclaveClient) UpdateConfig(context.Context, types.UpdateConfigRequest) error {
	return nil
}
func (s *stubEnclaveClient) GetConfigs(context.Context) ([]types.EnclaveConfig, error) {
	return nil, nil
}
func (s *stubEnclaveClient) GetCacheStats() map[string]interface{} { return nil }
func (s *stubEnclaveClient) Close() error                        { return nil }

func TestBroadcastConfigUpdate_DropsWhenProposalInFlight(t *testing.T) {
	stub := &stubEnclaveClient{}
	e := &RealExecutor{lggr: logger.Test(t), enclaveClient: stub}
	e.proposalInFlight.Store(true) // simulate an in-flight proposal

	err := e.broadcastConfigUpdate(context.Background(), [][]byte{{1, 2, 3}}, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, stub.getPublicKeysCalls, "must not contact enclaves while a proposal is already in flight")
	assert.True(t, e.proposalInFlight.Load(), "the in-flight flag owned by the other proposal must be left set")
}

// TestDONMembership_ConcurrentAccess exercises the accessors under the race detector
// to guard against regressions of the donMembers/donF data race.
func TestDONMembership_ConcurrentAccess(t *testing.T) {
	e := &RealExecutor{}
	e.setDONMembership([][]byte{{1}}, 1)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func(n int) { defer wg.Done(); e.setDONMembership([][]byte{{byte(n)}}, uint32(n)) }(i)
		go func() { defer wg.Done(); _, _ = e.getDONMembership() }()
		go func() {
			defer wg.Done()
			_ = e.validateEnclaveSigners(types.EnclaveConfig{Signers: [][]byte{{1}}, F: 0})
		}()
	}
	wg.Wait()
}
