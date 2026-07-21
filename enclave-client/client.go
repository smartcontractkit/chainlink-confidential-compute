// enclaveclient provides a client by which a pool of enclaves can be accessed to execute compute requests.
// The client is responsible for selecting an enclave from the pool, fetching public keys from a set of enclaves,
// sending compute requests to the enclaves, and validating attested responses.

package enclaveclient

import (
	"context"

	"github.com/smartcontractkit/confidential-compute/types"
)

type EnclaveClient interface {
	GetPublicKeys(ctx context.Context, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.EnclavePublicKeyData, error)
	ExecuteBatch(ctx context.Context, reqs []types.SignedComputeRequest, enclaveIDs [][32]byte) ([]types.ExecuteResponse, error)
	UpdateNodes(ctx context.Context, nodes []types.Enclave) error
	UpdateConfig(ctx context.Context, update types.UpdateConfigRequest) error
	GetConfigs(ctx context.Context) ([]types.EnclaveConfig, error)
	GetCacheStats() map[string]interface{}
	Close() error
}
