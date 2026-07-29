package enclaveselector

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

var _ EnclaveSelector = (*roundRobinEnclaveSelector)(nil)

type roundRobinEnclaveSelector struct {
	deadMu       sync.RWMutex
	deadEnclaves map[[32]byte]struct{}
}

// NewRoundRobinEnclaveSelector creates a new instance of RoundRobinEnclaveSelector. This enclave selector
// uses the hash of the request ID to select an enclave, resulting in a round-robin load balancing effect when requestIDs
// monotonically increase, and a pseudorandom load balancing effect when requestIDs are random.
func NewRoundRobinEnclaveSelector() *roundRobinEnclaveSelector {
	return &roundRobinEnclaveSelector{deadEnclaves: make(map[[32]byte]struct{})}
}

// SelectEnclaves selects an enclave node based on the request ID and enclave specifications.
// It uses a simple round-robin strategy based on the numeric representation of the request ID.
// Enclaves are first filtered by checkRequirements (a nil checker accepts all enclaves).
// Dead enclaves are skipped according to the selector's internal liveness map.
func (s *roundRobinEnclaveSelector) SelectEnclaves(enclaves []types.Enclave, requestID [32]byte, checkRequirements types.RequirementsChecker) ([]types.Enclave, error) {
	nodes := make([]types.Enclave, 0, len(enclaves))
	for _, enc := range enclaves {
		if checkRequirements == nil || checkRequirements(enc) {
			nodes = append(nodes, enc)
		}
	}

	// If no nodes match the allowed types, return an error.
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}

	baseIndex := calcMod(requestID, len(nodes))
	for offset := 0; offset < len(nodes); offset++ {
		selectedNode := nodes[(baseIndex+offset)%len(nodes)]
		if s.isEnclaveDead(selectedNode.EnclaveID) {
			continue
		}

		return []types.Enclave{selectedNode}, nil
	}

	return nil, fmt.Errorf("no live enclaves available")
}

func (s *roundRobinEnclaveSelector) SetEnclaveLiveness(enclaveID [32]byte, isAlive bool) {
	s.deadMu.Lock()
	defer s.deadMu.Unlock()

	if s.deadEnclaves == nil {
		s.deadEnclaves = make(map[[32]byte]struct{})
	}

	if isAlive {
		delete(s.deadEnclaves, enclaveID)
		return
	}

	s.deadEnclaves[enclaveID] = struct{}{}
}

func (s *roundRobinEnclaveSelector) isEnclaveDead(enclaveID [32]byte) bool {
	s.deadMu.RLock()
	_, isDead := s.deadEnclaves[enclaveID]
	s.deadMu.RUnlock()
	return isDead
}

// byteArrayMod takes a byte array x and a modulo value y, and returns bigInt(x) % y as an int.
func calcMod(b [32]byte, modulus int) int {
	bigInt := new(big.Int).SetBytes(b[:])
	return int(bigInt.Mod(bigInt, big.NewInt(int64(modulus))).Int64())
}
