// Package worker defines the private, one-shot coordinator/worker protocol.
package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"google.golang.org/protobuf/proto"
)

const (
	Version        = 1
	MaxReplyBytes  = 16 << 20
	Success        = "success"
	ExecutionError = "execution_error"
	SetupError     = "setup_error"
)

type GatewayConfig struct {
	URL            string
	RequestTimeout time.Duration
	RetryBackoff   time.Duration
	RetryTimeout   time.Duration
}

type Job struct {
	Version          int
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
	Version   int
	RequestID [32]byte
	Outcome   string
	Result    []byte
	Error     *types.ExecuteError `json:",omitempty"`
	Events    []types.MetricEvent `json:",omitempty"`
}

func (r Reply) Validate(id [32]byte) error {
	if r.Version != Version || r.RequestID != id {
		return errors.New("worker reply version or request ID mismatch")
	}
	switch r.Outcome {
	case Success:
		if r.Error != nil || r.Result == nil {
			return errors.New("invalid worker success reply")
		}
		var result sdkpb.ExecutionResult
		if err := proto.Unmarshal(r.Result, &result); err != nil {
			return errors.New("invalid worker result protobuf")
		}
	case ExecutionError, SetupError:
		if r.Error == nil || r.Error.Error == "" || r.Result != nil {
			return errors.New("invalid worker error reply")
		}
	default:
		return errors.New("unknown worker outcome")
	}
	return nil
}

// Decode accepts one object and EOF. The frame callback starts the parent's
// exit grace even if a worker writes a reply but never closes stdout.
func Decode(r io.Reader, limit int64, out any, frame func()) error {
	if limit <= 0 || limit == int64(^uint64(0)>>1) {
		return errors.New("invalid worker message limit")
	}
	lr := &io.LimitedReader{R: r, N: limit + 1}
	dec := json.NewDecoder(lr)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decoding worker message: %w", err)
	}
	if frame != nil {
		frame()
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("worker message has trailing data")
	}
	if lr.N == 0 {
		return errors.New("worker message exceeds limit")
	}
	return nil
}

func WriteReply(w io.Writer, reply Reply) error {
	data, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	if len(data)+1 > MaxReplyBytes {
		reply.Outcome = SetupError
		reply.Result, reply.Events = nil, nil
		reply.Error = &types.ExecuteError{Error: "worker response exceeds maximum allowed size", Code: 500}
		data, err = json.Marshal(reply)
		if err != nil {
			return err
		}
	}
	data = append(data, '\n')
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// Events bounds aggregate event storage, not just individual user-log lines.
// Encoded copies also prevent later helper mutations from changing the reply.
type Events struct {
	mu      sync.Mutex
	encoded []json.RawMessage
	bytes   int
	err     error
}

func (e *Events) Emit(name string, details map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return
	}
	b, err := json.Marshal(types.MetricEvent{Event: name, Details: details})
	if err != nil {
		e.err = errors.New("cannot encode worker event")
		return
	}
	if len(b)+1 > MaxReplyBytes-e.bytes {
		e.err = errors.New("worker events exceed maximum allowed size")
		e.encoded = nil
		return
	}
	e.bytes += len(b) + 1
	e.encoded = append(e.encoded, b)
}

func (e *Events) Snapshot() ([]types.MetricEvent, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return nil, e.err
	}
	events := make([]types.MetricEvent, len(e.encoded))
	for i, b := range e.encoded {
		if err := json.Unmarshal(b, &events[i]); err != nil {
			return nil, err
		}
	}
	return events, nil
}
