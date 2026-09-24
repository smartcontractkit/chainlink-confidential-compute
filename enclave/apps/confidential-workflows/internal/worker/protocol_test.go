package worker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func successReply(id [32]byte, value string) Reply {
	result, _ := proto.Marshal(&sdkpb.ExecutionResult{Result: &sdkpb.ExecutionResult_Value{Value: values.Proto(values.NewString(value))}})
	return Reply{Version: Version, RequestID: id, Outcome: Success, Result: result}
}

func TestReplyProtocol(t *testing.T) {
	r := successReply([32]byte{1}, "hello")
	var buf bytes.Buffer
	require.NoError(t, WriteReply(&buf, r))
	var decoded Reply
	require.NoError(t, Decode(bytes.NewReader(buf.Bytes()), MaxReplyBytes, &decoded, nil))
	require.NoError(t, decoded.Validate(r.RequestID))
	require.Error(t, decoded.Validate([32]byte{2}))
	for name, data := range map[string][]byte{
		"empty": nil, "truncated": buf.Bytes()[:10], "extra": append(bytes.Clone(buf.Bytes()), []byte("{}")...),
		"stdout log": []byte("logging\n{}"), "unknown": []byte(`{"Unexpected":1}`),
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, Decode(bytes.NewReader(data), MaxReplyBytes, &Reply{}, nil)) })
	}
	require.Error(t, Decode(bytes.NewReader(buf.Bytes()), int64(buf.Len()-1), &Reply{}, nil))
	r.Error = &types.ExecuteError{Error: "contradictory"}
	require.Error(t, r.Validate(r.RequestID))
	r.Error = nil
	r.Result = []byte("bad proto")
	require.Error(t, r.Validate(r.RequestID))
}

func TestSupportedExternalResponseFitsReply(t *testing.T) {
	// Exercise base64 expansion plus strings requiring JSON escaping near the
	// external envelope limit, including both metric representations.
	r := successReply([32]byte{1}, strings.Repeat("x", 5<<20))
	r.Events = []types.MetricEvent{{Event: "user_log", Details: map[string]any{"message": strings.Repeat("<\n", 180000)}}}
	external, err := json.Marshal(types.ExecuteResponse{Output: r.Result, MetricEvents: r.Events,
		Metrics: map[string]any{"user_log": r.Events[0].Details}})
	require.NoError(t, err)
	require.Less(t, len(external), types.MaxEnclaveResponseBodyBytes)
	var buf bytes.Buffer
	require.NoError(t, WriteReply(&buf, r))
	var decoded Reply
	require.NoError(t, Decode(&buf, MaxReplyBytes, &decoded, nil))
	require.Equal(t, Success, decoded.Outcome)
}

func TestEmptySDKResultIsDistinctFromMissingResult(t *testing.T) {
	result, err := proto.Marshal(&sdkpb.ExecutionResult{})
	require.NoError(t, err)
	r := Reply{Version: Version, Outcome: Success, Result: result}
	var buf bytes.Buffer
	require.NoError(t, WriteReply(&buf, r))
	var decoded Reply
	require.NoError(t, Decode(&buf, MaxReplyBytes, &decoded, nil))
	require.NoError(t, decoded.Validate(r.RequestID))
	decoded.Result = nil
	require.Error(t, decoded.Validate(r.RequestID))
}

func TestBoundedEventsAndReply(t *testing.T) {
	var events Events
	details := map[string]any{"message": "first"}
	events.Emit("user_log", details)
	details["message"] = "second"
	events.Emit("user_log", details)
	snapshot, err := events.Snapshot()
	require.NoError(t, err)
	require.Len(t, snapshot, 2)
	require.Equal(t, "first", snapshot[0].Details["message"])
	chunk := strings.Repeat("x", 1<<20)
	for range 20 {
		events.Emit("user_log", map[string]any{"message": chunk})
	}
	_, err = events.Snapshot()
	require.Error(t, err)
	r := successReply([32]byte{1}, strings.Repeat("x", MaxReplyBytes))
	var buf bytes.Buffer
	require.NoError(t, WriteReply(&buf, r))
	var reply Reply
	require.NoError(t, Decode(&buf, MaxReplyBytes, &reply, nil))
	require.NoError(t, reply.Validate(r.RequestID))
	require.Equal(t, SetupError, reply.Outcome)
}
