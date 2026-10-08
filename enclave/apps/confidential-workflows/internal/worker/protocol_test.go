package worker

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func successReply(value string) Reply {
	result, _ := proto.Marshal(&confworkflowtypes.ConfidentialWorkflowResponse{SdkExecutionResult: &sdkpb.ExecutionResult{
		Result: &sdkpb.ExecutionResult_Value{Value: values.Proto(values.NewString(value))}}})
	return Reply{Result: result}
}

func TestReplyProtocol(t *testing.T) {
	r := successReply("hello")
	data, err := json.Marshal(r)
	require.NoError(t, err)
	decoded, err := DecodeReply(data)
	require.NoError(t, err)
	require.Equal(t, r, decoded)
	for name, data := range map[string][]byte{
		"empty": nil, "truncated": data[:10], "extra": append(data, []byte("{}")...),
		"stdout log": []byte("logging\n{}"), "missing result": []byte("{}"), "null": []byte("null"),
		"empty error": []byte(`{"Error":{}}`),
	} {
		t.Run(name, func(t *testing.T) { _, err := DecodeReply(data); require.Error(t, err) })
	}
	r.Error = &types.ExecuteError{Error: "contradictory"}
	data, err = json.Marshal(r)
	require.NoError(t, err)
	_, err = DecodeReply(data)
	require.Error(t, err)
	r.Result = nil
	data, err = json.Marshal(r)
	require.NoError(t, err)
	decoded, err = DecodeReply(data)
	require.NoError(t, err)
	require.Equal(t, r, decoded)
}

func TestSupportedExternalResponseFitsReply(t *testing.T) {
	// Base64 expansion and escaped strings must fit the private envelope whenever
	// the existing external response fits, including both metric representations.
	r := successReply(strings.Repeat("x", 5<<20))
	r.Events = []types.MetricEvent{
		{Event: "user_log", Details: map[string]any{"message": strings.Repeat("<\n", 180000)}},
		{Event: "user_log", Details: map[string]any{"message": "second"}},
	}
	external, err := json.Marshal(types.ExecuteResponse{Output: r.Result, MetricEvents: r.Events,
		Metrics: map[string]any{"user_log": r.Events[1].Details}})
	require.NoError(t, err)
	require.Less(t, len(external), types.MaxEnclaveResponseBodyBytes)
	data, err := json.Marshal(r)
	require.NoError(t, err)
	require.Less(t, len(data), MaxReplyBytes)
	decoded, err := DecodeReply(data)
	require.NoError(t, err)
	require.Equal(t, r, decoded)
}

func TestEmptyResponseIsDistinctFromMissingResult(t *testing.T) {
	result, err := proto.Marshal(&confworkflowtypes.ConfidentialWorkflowResponse{})
	require.NoError(t, err)
	data, err := json.Marshal(Reply{Result: result})
	require.NoError(t, err)
	decoded, err := DecodeReply(data)
	require.NoError(t, err)
	require.NotNil(t, decoded.Result)
	require.Empty(t, decoded.Result)
}

func TestBoundedReply(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	out := replyBuffer{cancel: cancel}
	_, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", MaxReplyBytes+1)), MaxReplyBytes+1))
	if out.timer != nil {
		out.timer.Stop()
	}
	require.ErrorContains(t, err, "reply exceeds limit")
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.LessOrEqual(t, out.buf.Len(), MaxReplyBytes)
}
