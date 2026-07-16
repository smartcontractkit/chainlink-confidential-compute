package enclaveselector_test

import (
	"crypto/sha256"
	"testing"

	enclaveselector "github.com/smartcontractkit/confidential-compute/enclave-client/enclave-selector"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/stretchr/testify/assert"
)

// onlyType returns a checker that accepts enclaves of the given type. The selector treats
// the checker as an opaque predicate; translating sdk.Requirements into one is the executor's job.
func onlyType(et types.EnclaveType) types.RequirementsChecker {
	return func(enc types.Enclave) bool { return enc.EnclaveType == et }
}

func TestRandomEnclaveSelector_SelectEnclave(t *testing.T) {
	t.Parallel()
	selector := enclaveselector.NewRoundRobinEnclaveSelector()


	testNodes := []types.Enclave{
		{
			EnclaveID:   sha256.Sum256([]byte("node1")),
			EnclaveURL:  "url1",
			EnclaveType: types.EnclaveTypeNitro,
			Region:      "us-east-1",
		},
		{
			EnclaveID:   sha256.Sum256([]byte("node2")),
			EnclaveURL:  "url2",
			EnclaveType: types.EnclaveTypeSGX,
			Region:      "us-east-1",
		},
		{
			EnclaveID:   sha256.Sum256([]byte("node3")),
			EnclaveURL:  "url3",
			EnclaveType: types.EnclaveTypeNitro,
			Region:      "us-east-1",
		},
	}

	t.Run("selects node based on request hash", func(t *testing.T) {
		t.Parallel()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)

		assert.NoError(t, err)
		assert.NotNil(t, nodes[0])
		assert.Equal(t, 1, len(nodes))
		found := false
		for i, n := range testNodes {
			if n.EnclaveID == nodes[0].EnclaveID {
				assert.Equal(t, 1, i)
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("filters by allowed enclave types", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes, err := selector.SelectEnclaves(testNodes, req.RequestID, onlyType(types.EnclaveTypeNitro))

		assert.NoError(t, err)
		assert.NotNil(t, nodes[0])
		assert.Equal(t, types.EnclaveTypeNitro, nodes[0].EnclaveType)
	})

	t.Run("filters by allowed enclave types 2", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes, err := selector.SelectEnclaves(testNodes, req.RequestID, onlyType(types.EnclaveTypeSGX))

		assert.NoError(t, err)
		assert.NotNil(t, nodes[0])
		assert.Equal(t, types.EnclaveTypeSGX, nodes[0].EnclaveType)
	})

	t.Run("returns error when no nodes match allowed types", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes, err := selector.SelectEnclaves(testNodes, req.RequestID, func(types.Enclave) bool { return false })

		assert.Error(t, err)
		assert.Nil(t, nodes)
		assert.Contains(t, err.Error(), "no nodes available")
	})

	t.Run("returns error when node list is empty", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes, err := selector.SelectEnclaves([]types.Enclave{}, req.RequestID, nil)

		assert.Error(t, err)
		assert.Nil(t, nodes)
		assert.Contains(t, err.Error(), "no nodes available")
	})

	t.Run("consistent selection for same request", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes1, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(nodes1))

		nodes2, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(nodes2))

		assert.Equal(t, nodes1[0].EnclaveID, nodes2[0].EnclaveID)
	})

	t.Run("skips dead enclave and picks next candidate", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes0, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)

		selector.SetEnclaveLiveness(nodes0[0].EnclaveID, false)

		nodes1, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)

		assert.NotEqual(t, nodes0[0].EnclaveID, nodes1[0].EnclaveID)
	})

	t.Run("dead enclave becomes selectable again after being marked live", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes0, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)

		selector.SetEnclaveLiveness(nodes0[0].EnclaveID, false)
		nodes1, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)
		assert.NotEqual(t, nodes0[0].EnclaveID, nodes1[0].EnclaveID)

		selector.SetEnclaveLiveness(nodes0[0].EnclaveID, true)
		nodes2, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.NoError(t, err)

		assert.Equal(t, nodes0[0].EnclaveID, nodes2[0].EnclaveID)
	})

	t.Run("returns error when all eligible nodes are dead", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		for _, node := range testNodes {
			selector.SetEnclaveLiveness(node.EnclaveID, false)
		}

		nodes, err := selector.SelectEnclaves(testNodes, req.RequestID, nil)
		assert.Error(t, err)
		assert.Nil(t, nodes)
		assert.Contains(t, err.Error(), "no live enclaves available")
	})

	t.Run("skips dead enclave after type filtering", func(t *testing.T) {
		t.Parallel()
		selector := enclaveselector.NewRoundRobinEnclaveSelector()

		req := &types.ComputeRequest{
			RequestID: sha256.Sum256([]byte("request1")),
		}

		nodes0, err := selector.SelectEnclaves(testNodes, req.RequestID, onlyType(types.EnclaveTypeNitro))
		assert.NoError(t, err)
		selector.SetEnclaveLiveness(nodes0[0].EnclaveID, false)

		nodes1, err := selector.SelectEnclaves(testNodes, req.RequestID, onlyType(types.EnclaveTypeNitro))
		assert.NoError(t, err)

		assert.Equal(t, types.EnclaveTypeNitro, nodes0[0].EnclaveType)
		assert.Equal(t, types.EnclaveTypeNitro, nodes1[0].EnclaveType)
		assert.NotEqual(t, nodes0[0].EnclaveID, nodes1[0].EnclaveID)
	})
}
