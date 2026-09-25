// Package worker defines the private, one-shot coordinator/worker protocol.
package worker

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const MaxReplyBytes = 16 << 20

type GatewayConfig struct {
	URL            string
	RequestTimeout time.Duration
	RetryBackoff   time.Duration
	RetryTimeout   time.Duration
}

type Job struct {
	Limits           wasmlimits.Config
	RequestID        [32]byte
	Execution        []byte
	Binary           []byte
	Config           types.EnclaveConfig
	Gateway          GatewayConfig
	HTTPTimeout      time.Duration
	ExecutionTimeout time.Duration
	SignedRequests   []types.SignedComputeRequest
	Key              *keychain.BoxKeySnapshot
	KeyError         string
}

func (Job) String() string   { return "[private execution job]" }
func (Job) GoString() string { return "[private execution job]" }

type Reply struct {
	// An empty protobuf is valid; nil means the result is absent.
	Result []byte
	Error  *types.ExecuteError `json:",omitempty"`
	Events []types.MetricEvent `json:",omitempty"`
}

func DecodeReply(data []byte) (Reply, error) {
	var reply Reply
	if err := json.Unmarshal(data, &reply); err != nil {
		return Reply{}, err
	}
	if (reply.Result == nil) == (reply.Error == nil) || (reply.Error != nil && reply.Error.Error == "") {
		return Reply{}, errors.New("worker reply must contain exactly one result or error")
	}
	return reply, nil
}
