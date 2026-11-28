package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	httpserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// overrideLimits mirrors the INCIDENT-2784 customer's owner override, which is
// above the CRE defaults of 5 calls and 10 KB requests.
func overrideLimits() *confworkflowtypes.ExecutionLimits {
	return &confworkflowtypes.ExecutionLimits{
		HttpAction: &confworkflowtypes.HTTPActionLimits{
			CallLimit:              proto.Uint32(20),
			RequestSizeLimitBytes:  proto.Uint64(200_000),
			ResponseSizeLimitBytes: proto.Uint64(100_000),
			ConnectionTimeout:      durationpb.New(10 * time.Second),
		},
	}
}

// sendHTTPAction issues one http-actions call through the helper and returns
// the capability error, if any.
func sendHTTPAction(t *testing.T, h *enclaveExecutionHelper, url string, body []byte) string {
	t.Helper()
	payload := &anypb.Any{}
	require.NoError(t, anypb.MarshalFrom(payload, &httpcap.Request{Url: url, Method: "POST", Body: body}, proto.MarshalOptions{Deterministic: true}))
	resp, err := h.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:      httpserver.ClientID,
		Method:  "SendRequest",
		Payload: payload,
	})
	require.NoError(t, err)
	return resp.GetError()
}

func limitsServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// Without limits from the DON the enclave applies none, whatever the CRE
// defaults are: 6 calls and a 100 KB body exceed the defaults but must pass.
func TestHTTPActionLimits_AbsentLimitsApplyNothing(t *testing.T) {
	url := limitsServer(t)
	for _, limits := range []*confworkflowtypes.ExecutionLimits{
		nil,
		{Wasm: &confworkflowtypes.WASMLimits{}},
	} {
		metrics := &recordingEmitter{}
		h := &enclaveExecutionHelper{logger: logger.Test(t), emitter: metrics, httpFetcher: permissiveFetcher(), httpLimits: newHTTPActionLimits(limits)}
		require.Nil(t, h.httpLimits)
		for range 6 {
			assert.Empty(t, sendHTTPAction(t, h, url, []byte(strings.Repeat("x", 100_000))))
		}
		assert.Zero(t, metrics.countOf("cre_limit_exceeded"))
	}
}

func TestHTTPActionLimits_AppliesOverride(t *testing.T) {
	url := limitsServer(t)
	metrics := &recordingEmitter{}
	h := &enclaveExecutionHelper{logger: logger.Test(t), emitter: metrics, httpFetcher: permissiveFetcher(), httpLimits: newHTTPActionLimits(overrideLimits())}

	assert.Empty(t, sendHTTPAction(t, h, url, []byte(strings.Repeat("x", 100_000))), "the override allows a body over the 10 KB default")
	for range 19 {
		assert.Empty(t, sendHTTPAction(t, h, url, nil))
	}
	errMsg := sendHTTPAction(t, h, url, nil)
	assert.Equal(t, "http-actions: capability call limit exceeded (PerWorkflow.HTTPAction.CallLimit: 20)", errMsg)

	require.Equal(t, 1, metrics.countOf("cre_limit_exceeded"))
	d := metrics.lastDetails("cre_limit_exceeded")
	assert.Equal(t, "PerWorkflow.HTTPAction.CallLimit", d["limit_key"])
	assert.Equal(t, httpserver.ClientID, d["capability_id"])

	h = &enclaveExecutionHelper{logger: logger.Test(t), emitter: metrics, httpFetcher: permissiveFetcher(), httpLimits: newHTTPActionLimits(overrideLimits())}
	errMsg = sendHTTPAction(t, h, url, []byte(strings.Repeat("x", 200_000)))
	assert.Contains(t, errMsg, "request exceeds PerWorkflow.HTTPAction.RequestSizeLimit limit 200000 bytes")
}

func TestNewHTTPActionLimits_PresenceAndBounds(t *testing.T) {
	l := newHTTPActionLimits(&confworkflowtypes.ExecutionLimits{
		HttpAction: &confworkflowtypes.HTTPActionLimits{
			CallLimit:              proto.Uint32(0),
			ResponseSizeLimitBytes: proto.Uint64(^uint64(0)),
			ConnectionTimeout:      durationpb.New(-time.Second),
		},
	})
	require.NotNil(t, l)
	require.NotNil(t, l.callLimit, "an explicit zero is a limit, not an absent one")
	assert.Zero(t, *l.callLimit)
	assert.Nil(t, l.fetch.RequestSizeLimit)
	require.NotNil(t, l.fetch.ResponseSizeLimit)
	assert.Positive(t, *l.fetch.ResponseSizeLimit, "values beyond int64 clamp instead of wrapping")
	assert.Nil(t, l.fetch.ConnectionTimeout, "a negative timeout is ignored")
	assert.True(t, l.countCall(), "CallLimit 0 rejects the first call")
}
