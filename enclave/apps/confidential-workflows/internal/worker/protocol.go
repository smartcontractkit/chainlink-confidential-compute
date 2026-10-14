// Package worker defines the private, one-shot coordinator/worker protocol.
package worker

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const MaxReplyBytes = 16 << 20

// GatewayConfig carries gateway settings shared by the dispatcher factory and workers.
type GatewayConfig struct {
	// URL is the gateway endpoint(s) for remote dispatch, comma-separated.
	URL string
	// RequestTimeout caps a single enclave->gateway HTTP exchange; zero disables it.
	RequestTimeout time.Duration
	// RetryBackoff paces successive gateway round-trips after a transient failure.
	RetryBackoff time.Duration
	// RetryTimeout bounds all attempts and backoffs for one capability call or secret fetch.
	RetryTimeout time.Duration
}

type HTTPActionLimits struct {
	CallLimit int
	Fetch     httpfetch.Limits
}

type Job struct {
	HTTPActionLimits  HTTPActionLimits
	Limits            wasmlimits.Config
	RequestID         [32]byte
	Execution         []byte
	ArtifactPath      string
	Config            types.EnclaveConfig
	Gateway           GatewayConfig
	HTTPTimeout       time.Duration
	ExecutionDeadline time.Time
	SignedRequests    []types.SignedComputeRequest
	Key               *keychain.BoxKeySnapshot
	KeyError          string
}

func (Job) String() string   { return "[private execution job]" }
func (Job) GoString() string { return "[private execution job]" }

type Reply struct {
	// Result is the encoded ConfidentialWorkflowResponse. Empty is valid; nil is absent.
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
