package framework

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

func TestValidateEnclaveSigners(t *testing.T) {
	memberA := []byte{1, 2, 3}
	memberB := []byte{4, 5, 6}
	memberC := []byte{7, 8, 9}

	sorted := [][]byte{memberA, memberB, memberC}
	slices.SortFunc(sorted, bytes.Compare)

	t.Run("passes when signers and F match", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 1}
		config := types.EnclaveConfig{
			Signers: [][]byte{memberC, memberA, memberB}, // unsorted
			F:       1,
		}
		require.NoError(t, e.validateEnclaveSigners(config))
	})

	t.Run("fails when F is below DON minimum", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 2}
		config := types.EnclaveConfig{
			Signers: [][]byte{memberA, memberB, memberC},
			F:       1,
		}
		err := e.validateEnclaveSigners(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enclave F value 1 does not match DON F value 2")
	})

	t.Run("passes when F exceeds DON minimum", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 1}
		config := types.EnclaveConfig{
			Signers: [][]byte{memberC, memberA, memberB},
			F:       2,
		}
		require.NoError(t, e.validateEnclaveSigners(config))
	})

	t.Run("fails when signers do not match", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 1}
		config := types.EnclaveConfig{
			Signers: [][]byte{memberA, memberB, {99, 99, 99}},
			F:       1,
		}
		err := e.validateEnclaveSigners(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enclave signers do not match DON members")
	})

	t.Run("fails when signer count differs", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 1}
		config := types.EnclaveConfig{
			Signers: [][]byte{memberA, memberB},
			F:       1,
		}
		err := e.validateEnclaveSigners(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enclave signers do not match DON members")
	})

	t.Run("errors when donMembers is empty", func(t *testing.T) {
		e := &RealExecutor{donMembers: nil, donF: 0}
		config := types.EnclaveConfig{
			Signers: [][]byte{{99}},
			F:       5,
		}
		err := e.validateEnclaveSigners(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DON members not set")
	})

	t.Run("F mismatch checked before signers", func(t *testing.T) {
		e := &RealExecutor{donMembers: sorted, donF: 3}
		config := types.EnclaveConfig{
			Signers: [][]byte{{99}}, // wrong signers AND wrong F
			F:       1,
		}
		err := e.validateEnclaveSigners(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enclave F value 1 does not match DON F value 3")
	})
}
