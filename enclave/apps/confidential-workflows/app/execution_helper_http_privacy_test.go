package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	httpserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type httpRoundTripFunc func(*http.Request) (*http.Response, error)

func (f httpRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type httpErrorBody struct{ err error }

func (b httpErrorBody) Read([]byte) (int, error) { return 0, b.err }
func (b httpErrorBody) Close() error             { return nil }

func TestCallCapability_HTTPFailuresDoNotDiscloseRequestData(t *testing.T) {
	const secret = "confidential-canary"
	const rawURL = "https://" + secret + ".example/" + secret + "?token=" + secret
	tests := []struct {
		name      string
		input     *httpcap.Request
		payload   *anypb.Any
		transport httpRoundTripFunc
		want      string
	}{
		{name: "redirect", transport: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {rawURL + "-next"}}, Body: http.NoBody}, nil
		}, want: "http-actions: http request failed: redirects are not allowed"},
		{name: "certificate", transport: func(*http.Request) (*http.Response, error) {
			return nil, &tls.CertificateVerificationError{Err: x509.HostnameError{Host: secret, Certificate: &x509.Certificate{}}}
		}, want: "http-actions: http request failed: TLS certificate verification failed"},
		{name: "TLS alert", transport: func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "remote error", Err: tls.AlertError(20)}
		}, want: "http-actions: http request failed: transport failure"},
		{name: "unknown transport", transport: func(*http.Request) (*http.Response, error) {
			return nil, errors.New(secret)
		}, want: "http-actions: http request failed: transport failure"},
		{name: "read response", transport: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: httpErrorBody{errors.New(secret)}}, nil
		}, want: "http-actions: reading response failed"},
		{name: "invalid method", input: &httpcap.Request{Url: rawURL, Method: secret}, want: "http-actions: method not allowed"},
		{name: "invalid URL", input: &httpcap.Request{Url: "https://" + secret + ".example/%zz", Method: "GET"}, want: "http-actions: building request failed"},
		{name: "invalid payload type", payload: &anypb.Any{TypeUrl: secret}, want: "http-actions: unmarshalling request failed"},
		{name: "invalid payload bytes", payload: &anypb.Any{TypeUrl: "type.googleapis.com/" + string((&httpcap.Request{}).ProtoReflect().Descriptor().FullName()), Value: []byte{0xff}}, want: "http-actions: unmarshalling request failed"},
		{name: "invalid response encoding", transport: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Value": {secret + "\xff"}}, Body: http.NoBody}, nil
		}, want: "http-actions: marshalling response failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := util.NewRestrictedHTTPClient()
			calls := 0
			client.Client.Transport = httpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, 1, calls, "redirect target must not be requested")
				require.NotNil(t, tt.transport, "invalid inputs must not reach transport")
				assert.Equal(t, rawURL, req.URL.String())
				assert.Equal(t, secret, req.Header.Get("Authorization"))
				return tt.transport(req)
			})
			em := server.NewResponseEmitter()
			h := &enclaveExecutionHelper{emitter: em, httpFetcher: httpfetch.NewFetcherWithClient(httpfetch.DefaultPolicy(), client)}
			payload := tt.payload
			if payload == nil {
				input := tt.input
				if input == nil {
					input = &httpcap.Request{Url: rawURL, Method: "GET", MultiHeaders: map[string]*httpcap.HeaderValues{"Authorization": {Values: []string{secret}}}}
				}
				var err error
				payload, err = anypb.New(input)
				require.NoError(t, err)
			}
			resp, err := h.CallCapability(context.Background(), &sdkpb.CapabilityRequest{Id: httpserver.ClientID, Method: "SendRequest", Payload: payload})
			require.NoError(t, err)
			require.Equal(t, tt.want, resp.GetError())
			require.Nil(t, resp.GetPayload())
			metrics, events := em.Snapshot()
			require.Len(t, events, 3)
			assert.Equal(t, "capability_finished", events[2].Event)
			assert.Equal(t, tt.want, events[2].Details["error"])
			assert.Equal(t, "capability", events[2].Details["error_type"])
			assert.Equal(t, false, events[2].Details["success"])

			// Both successful workflows that handle the failure and failed workflows
			// export these events, in ordered and legacy representations.
			wire, err := json.Marshal(types.ExecuteResponse{Metrics: metrics, MetricEvents: events})
			require.NoError(t, err)
			assert.NotContains(t, string(wire), secret)
			recorder := httptest.NewRecorder()
			em.WriteErrorResponse(recorder, resp.GetError(), http.StatusInternalServerError)
			assert.NotContains(t, recorder.Body.String(), secret)
			assert.NotContains(t, recorder.Body.String(), url.QueryEscape(secret))
		})
	}
}

func TestCallCapability_HTTPResponseDataIsNotTelemetry(t *testing.T) {
	const secret = "confidential-response-canary"
	client := &http.Client{Transport: httpRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized, Header: http.Header{"X-Private": {secret}},
			Body: io.NopCloser(strings.NewReader(secret)),
		}, nil
	})}
	em := server.NewResponseEmitter()
	h := &enclaveExecutionHelper{emitter: em, httpFetcher: httpfetch.NewFetcherWithClient(httpfetch.DefaultPolicy(), client)}
	payload, err := anypb.New(&httpcap.Request{Url: "https://example.com", Method: "GET"})
	require.NoError(t, err)
	resp, err := h.CallCapability(context.Background(), &sdkpb.CapabilityRequest{Id: httpserver.ClientID, Method: "SendRequest", Payload: payload})
	require.NoError(t, err)
	require.Empty(t, resp.GetError())
	var out httpcap.Response
	require.NoError(t, resp.GetPayload().UnmarshalTo(&out))
	assert.EqualValues(t, http.StatusUnauthorized, out.StatusCode)
	assert.Equal(t, secret, string(out.Body))
	assert.Equal(t, secret, out.MultiHeaders["X-Private"].Values[0])
	wire, err := json.Marshal(em.GetMetricEvents())
	require.NoError(t, err)
	assert.NotContains(t, string(wire), secret)
}

func TestExecute_HTTPFailureDoesNotDiscloseRequestData(t *testing.T) {
	const secret = "confidential-wasm-canary"
	raw := buildTestWasm(t, "http-call")
	var compressed bytes.Buffer
	w := brotli.NewWriter(&compressed)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	binary := compressed.Bytes()
	hash := sha256.Sum256(binary)

	client := util.NewRestrictedHTTPClient()
	calls := 0
	client.Client.Transport = httpRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, 1, calls, "redirect target must not be requested")
		assert.Contains(t, req.URL.String(), secret)
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/" + secret + "?token=" + secret}}, Body: http.NoBody}, nil
	})
	app, locator := newStorageBackedApp(t, binary, WithHTTPFetcher(httpfetch.NewFetcherWithClient(httpfetch.DefaultPolicy(), client)))
	lggr, logs := logger.TestObserved(t, zapcore.DebugLevel)
	app.(*confidentialWorkflowsApp).logger = lggr
	execution := makeExecution(t, "wf-http-error-privacy", locator, hash[:])
	execution.SdkExecuteRequest.Config = []byte("https://example.com/" + secret + "?token=" + secret)
	data, err := proto.Marshal(execution)
	require.NoError(t, err)
	em := server.NewResponseEmitter()
	output, execErr := app.Execute([32]byte{1}, types.AppIDConfidentialWorkflows, data, nil, em)
	require.Nil(t, execErr)
	require.Equal(t, 1, calls)
	var result confworkflowtypes.ConfidentialWorkflowResponse
	require.NoError(t, proto.Unmarshal(output, &result))
	require.Contains(t, result.GetSdkExecutionResult().GetError(), "redirects are not allowed")
	assert.NotContains(t, result.String(), secret)
	metrics, events := em.Snapshot()
	finished := metrics["capability_finished"].(map[string]any)
	assert.Equal(t, false, finished["success"])
	assert.Equal(t, "http-actions: http request failed: redirects are not allowed", finished["error"])
	wire, err := json.Marshal(types.ExecuteResponse{Output: output, Metrics: metrics, MetricEvents: events})
	require.NoError(t, err)
	assert.NotContains(t, string(wire), secret)
	for _, entry := range logs.All() {
		fields, err := json.Marshal(entry.ContextMap())
		require.NoError(t, err)
		assert.NotContains(t, entry.Message+string(fields), secret)
	}
}
