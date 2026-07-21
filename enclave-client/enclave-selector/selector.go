// This package provides the `EnclaveSelector` interface to select a subset of enclaves from a pool.
// It also provides an implementation that uses pseudorandom selection.

package enclaveselector

import (
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

type EnclaveSelector interface {
	SelectEnclaves(enclaves []types.Enclave, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.Enclave, error)
	SetEnclaveLiveness(enclaveID [32]byte, isAlive bool)
}
