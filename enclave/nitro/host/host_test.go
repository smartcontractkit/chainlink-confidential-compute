package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	confhttptypes "github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type mockRoundTripper struct {
	response *http.Response
	requests []*http.Request
	err      error
	delay    time.Duration // optional delay before responding
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.requests = append(m.requests, req)
	return m.response, m.err
}

func observedFieldsByEvent(t *testing.T, logs *observer.ObservedLogs, event string) map[string]any {
	t.Helper()
	for _, entry := range logs.All() {
		fields := entry.ContextMap()
		if fields["event"] == event {
			return fields
		}
	}
	t.Fatalf("missing log event %s; got %v", event, logs.All())
	return nil
}

func TestLogPublicDataConfidentialHTTP(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	req := &confhttptypes.Request{
		Url:    "https://example.test/path?visible=1",
		Method: http.MethodPost,
		Body:   &confhttptypes.Request_BodyString{BodyString: "hello"},
		MultiHeaders: map[string]*confhttptypes.HeaderValues{
			"Authorization": &confhttptypes.HeaderValues{Values: []string{"public-scheme-only"}},
			"X-Trace":       &confhttptypes.HeaderValues{Values: []string{"trace-id"}},
		},
		TemplatePublicValues: map[string]string{
			"city": "Lisbon",
		},
		CustomRootCaCertPem: []byte("pem"),
		Timeout:             durationpb.New(2 * time.Second),
		EncryptOutput:       true,
	}
	publicData, err := proto.Marshal(req)
	require.NoError(t, err)

	logPublicData(lggr, types.AppIDConfidentialHTTP, publicData)

	fields := observedFieldsByEvent(t, logs, "PUBLIC_DATA")
	assert.Equal(t, types.AppIDConfidentialHTTP, fields["appID"])
	assert.Equal(t, "confidential_http_request", fields["publicDataType"])
	assert.Equal(t, req.Url, fields["url"])
	assert.Equal(t, req.Method, fields["method"])
	assert.Equal(t, "string", fields["bodyKind"])
	assert.Equal(t, int64(5), fields["bodyLen"])
	assert.Equal(t, []any{"Authorization", "X-Trace"}, fields["headerNames"])
	assert.Equal(t, []any{"city"}, fields["templatePublicValueKeys"])
	assert.Equal(t, int64(3), fields["customRootCACertPEMLen"])
	assert.Equal(t, "2s", fields["timeout"])
	assert.Equal(t, true, fields["encryptOutput"])
}

func TestLogPublicDataConfidentialWorkflows(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)
	execution := &confworkflowtypes.WorkflowExecution{
		WorkflowId:   "workflow-id",
		BinaryUrl:    "storage://workflow-binary",
		BinaryHash:   []byte{0xab, 0xcd},
		Owner:        "0xowner",
		ExecutionId:  "execution-id",
		OrgId:        "org-id",
		Requirements: &sdkpb.Requirements{},
		Restrictions: &sdkpb.Restrictions{},
		SdkExecuteRequest: &sdkpb.ExecuteRequest{
			Config:          []byte("cfg"),
			MaxResponseSize: 123,
			Request: &sdkpb.ExecuteRequest_Trigger{
				Trigger: &sdkpb.Trigger{Id: 7},
			},
		},
	}
	publicData, err := proto.Marshal(execution)
	require.NoError(t, err)

	logPublicData(lggr, types.AppIDConfidentialWorkflows, publicData)

	fields := observedFieldsByEvent(t, logs, "PUBLIC_DATA")
	assert.Equal(t, types.AppIDConfidentialWorkflows, fields["appID"])
	assert.Equal(t, "workflow_execution", fields["publicDataType"])
	assert.Equal(t, "workflow-id", fields["workflowID"])
	assert.Equal(t, "execution-id", fields["executionID"])
	assert.Equal(t, "0xowner", fields["owner"])
	assert.Equal(t, "org-id", fields["orgID"])
	assert.Equal(t, "storage://workflow-binary", fields["binaryURL"])
	assert.Equal(t, "abcd", fields["binaryHash"])
	assert.Equal(t, true, fields["requirementsPresent"])
	assert.Equal(t, true, fields["restrictionsPresent"])
	assert.Equal(t, "trigger", fields["executeRequestKind"])
	assert.Equal(t, uint64(7), fields["triggerID"])
	assert.Equal(t, int64(3), fields["executeRequestConfigLen"])
	assert.Equal(t, uint64(123), fields["maxResponseSize"])
}

func TestLogPublicDataInvalidProto(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)

	logPublicData(lggr, types.AppIDConfidentialHTTP, []byte{0xff})

	fields := observedFieldsByEvent(t, logs, "PUBLIC_DATA_DECODE_ERR")
	assert.Equal(t, types.AppIDConfidentialHTTP, fields["appID"])
	assert.Equal(t, int64(1), fields["publicDataLen"])
	assert.NotNil(t, fields["error"])
}

func TestLogPublicDataUnknownApp(t *testing.T) {
	lggr, logs := cllogger.TestObservedSugared(t, zapcore.DebugLevel)

	logPublicData(lggr, "unknown-app", []byte("opaque"))

	fields := observedFieldsByEvent(t, logs, "PUBLIC_DATA_UNSUPPORTED")
	assert.Equal(t, "unknown-app", fields["appID"])
	assert.Equal(t, int64(6), fields["publicDataLen"])
}

func TestHandleGetPublicKeys(t *testing.T) {
	t.Run("forwards requestID query param to enclave", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"publicKey":"abc123"}]`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			},
		}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, "/publicKeys?requestID=deadbeef", nil)
		w := httptest.NewRecorder()
		host.handleGetPublicKeys(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, mockTransport.requests, 1)
		assert.Equal(t, "deadbeef", mockTransport.requests[0].URL.Query().Get("requestID"))
	})

	t.Run("no requestID omits query param", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"publicKey":"abc123"}]`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			},
		}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, "/publicKeys", nil)
		w := httptest.NewRecorder()
		host.handleGetPublicKeys(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, mockTransport.requests, 1)
		assert.Empty(t, mockTransport.requests[0].URL.Query().Get("requestID"))
	})

	t.Run("rejects non-GET method", func(t *testing.T) {
		host := NewHostServer(context.Background(), &http.Client{})

		req := httptest.NewRequest(http.MethodPost, "/publicKeys", nil)
		w := httptest.NewRecorder()
		host.handleGetPublicKeys(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("returns 500 when enclave unreachable", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			err: errors.New("vsock connection refused"),
		}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, "/publicKeys?requestID=aabb", nil)
		w := httptest.NewRecorder()
		host.handleGetPublicKeys(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "failed to communicate with enclave")
	})

	t.Run("proxies enclave response headers and status", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString("bad request ID")),
				Header:     http.Header{"X-Custom": []string{"value1"}},
			},
		}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, "/publicKeys?requestID=short", nil)
		w := httptest.NewRecorder()
		host.handleGetPublicKeys(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "value1", w.Header().Get("X-Custom"))
		assert.Equal(t, "bad request ID", w.Body.String())
	})
}

func TestHandleMemory(t *testing.T) {
	t.Run("forwards GET to enclave and relays response", func(t *testing.T) {
		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"usedMB":32}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			},
		}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, types.MemoryPath, nil)
		w := httptest.NewRecorder()
		host.handleMemory(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, mockTransport.requests, 1)
		assert.Equal(t, http.MethodGet, mockTransport.requests[0].Method)
		assert.Equal(t, types.MemoryPath, mockTransport.requests[0].URL.Path)
		assert.Equal(t, `{"usedMB":32}`, w.Body.String())
	})

	t.Run("rejects non-GET method", func(t *testing.T) {
		host := NewHostServer(context.Background(), &http.Client{})

		req := httptest.NewRequest(http.MethodPost, types.MemoryPath, nil)
		w := httptest.NewRecorder()
		host.handleMemory(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("returns 500 when enclave unreachable", func(t *testing.T) {
		mockTransport := &mockRoundTripper{err: errors.New("vsock connection refused")}
		host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

		req := httptest.NewRequest(http.MethodGet, types.MemoryPath, nil)
		w := httptest.NewRecorder()
		host.handleMemory(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "failed to communicate with enclave")
	})
}

func TestHandleSetConfig(t *testing.T) {
	config := types.EnclaveConfig{
		Signers:         [][]byte{[]byte("test-signer")},
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               1,
	}
	configBytes := util.MustMarshal(t, config)

	configResp := types.SetConfigResponse{
		Config:      config,
		Attestation: []byte("test-attestation"),
	}
	respBytes := util.MustMarshal(t, configResp)

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	mockTransport := &mockRoundTripper{response: mockResp}

	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

	configReq := types.ConfigRequest{
		Config: configBytes,
	}
	reqBytes := util.MustMarshal(t, configReq)

	req := httptest.NewRequest(http.MethodPost, "/config", bytes.NewReader(reqBytes))
	w := httptest.NewRecorder()

	host.handleSetConfig(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, uint32(2), host.config.T)
	assert.Equal(t, uint32(1), host.config.F)
}

func TestHandleExecuteWithBatchingAndCaching(t *testing.T) {
	const numRequests = 3
	signerKeys := make([]*ed25519.PrivateKey, numRequests)
	signers := make([][]byte, numRequests)

	for i := 0; i < numRequests; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	mockExecResponse := types.ExecuteResponse{
		RequestID:   sha256.Sum256([]byte("test-request-id-batching-caching")),
		Output:      []byte("test-outputs"),
		Attestation: []byte("test-attestation"),
	}
	respBytes := util.MustMarshal(t, mockExecResponse)

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	mockTransport := &mockRoundTripper{response: mockResp}

	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})

	host.config = config

	executeRequests := make([]*http.Request, numRequests)
	recorders := make([]*httptest.ResponseRecorder, numRequests)

	for i := 0; i < numRequests; i++ {
		computeReq := types.ComputeRequest{
			RequestID:   sha256.Sum256([]byte("test-request-id-batching-caching")),
			Ciphertexts: [][]byte{[]byte("test-ciphertext")},
			PublicData:  []byte("test-public-data"),
		}

		hash := computeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*signerKeys[i], prefixedHash)
		execReq := types.SignedComputeRequest{
			ComputeRequest: computeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		executeRequests[i] = httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		recorders[i] = httptest.NewRecorder()
	}

	// Handle first two requests which should be queued
	for i := 0; i < numRequests-1; i++ {
		go func(idx int) {
			host.handleExecute(recorders[idx], executeRequests[idx])
		}(i)
	}

	// Give time for the first two requests to be processed
	time.Sleep(100 * time.Millisecond)

	// No batch should be processed yet
	assert.Empty(t, mockTransport.requests)

	// Submit the third request which should trigger processing
	host.handleExecute(recorders[numRequests-1], executeRequests[numRequests-1])

	// Assert that the batch was processed.
	success := false
	for i := 0; i < 100; i++ {
		if len(mockTransport.requests) == 1 {
			success = true
			for _, rec := range recorders {
				if rec.Body.Len() == 0 {
					success = false
				}
			}
			if success {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.True(t, success, "batch request was not sent within timeout")

	// Verify that the batch request contains all three original requests
	var enclaveReqs []types.SignedComputeRequest
	bodyBytes, err := io.ReadAll(mockTransport.requests[0].Body)
	require.NoError(t, err)
	err = json.Unmarshal(bodyBytes, &enclaveReqs)
	require.NoError(t, err)
	assert.Len(t, enclaveReqs, numRequests)
	for i := 0; i < numRequests; i++ {
		assert.Equal(t, sha256.Sum256([]byte("test-request-id-batching-caching")), enclaveReqs[i].RequestID)
	}

	// Check that all client requests got the same response
	for i, rec := range recorders {
		assert.Equal(t, http.StatusOK, rec.Code, "Response recorder %d has unexpected status code", i)
		var resp types.ExecuteResponse
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err, "Failed to unmarshal response %d", i)
		assert.Equal(t, mockExecResponse.RequestID, resp.RequestID)
		assert.Equal(t, mockExecResponse.Output, resp.Output)
	}

	// Now test a laggard request after the batch already processed
	laggardPubKey, laggardKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Add the laggard's address to the allowed signers
	config.Signers = append(config.Signers, laggardPubKey)
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-id-batching-caching")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	hash := computeReq.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	signature := ed25519.Sign(laggardKey, prefixedHash)

	laggardExecReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      signature,
	}

	laggardReqBytes := util.MustMarshal(t, laggardExecReq)
	laggardRecorder := httptest.NewRecorder()
	laggardReq := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(laggardReqBytes))

	host.handleExecute(laggardRecorder, laggardReq)

	// No new requests should be sent to the enclave
	assert.Len(t, mockTransport.requests, 1)

	// The laggard should receive the cached response
	assert.Equal(t, http.StatusOK, laggardRecorder.Code)
	var laggardResp types.ExecuteResponse
	err = json.Unmarshal(laggardRecorder.Body.Bytes(), &laggardResp)
	require.NoError(t, err)
	assert.Equal(t, mockExecResponse.RequestID, laggardResp.RequestID)
	assert.Equal(t, mockExecResponse.Output, laggardResp.Output)
}

func TestHandleExecuteWithZeroTF(t *testing.T) {
	config := types.EnclaveConfig{
		T: 0,
		F: 0,
	}

	host := NewHostServer(context.Background(), nil)

	host.config = config

	execReq := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:   sha256.Sum256([]byte("test-request-id")),
			Ciphertexts: [][]byte{[]byte("test-ciphertext")},
			PublicData:  []byte("test-public-data"),
		},
	}
	reqBytes := util.MustMarshal(t, execReq)

	req := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
	w := httptest.NewRecorder()

	host.handleExecute(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "service not accepting requests")
}

// TestHandleExecuteWithBatchError verifies that specific errors from processBatch
// are properly propagated to clients in the HTTP response.
func TestHandleExecuteWithBatchError(t *testing.T) {
	const numRequests = 3
	signerKeys := make([]*ed25519.PrivateKey, numRequests)
	signers := make([][]byte, numRequests)

	for i := 0; i < numRequests; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	// Create a mockRoundTripper that returns an error
	specificError := errors.New("connection to enclave failed: timeout")
	mockTransport := &mockRoundTripper{
		err: specificError,
	}

	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})
	host.config = config

	executeRequests := make([]*http.Request, numRequests)
	recorders := make([]*httptest.ResponseRecorder, numRequests)

	for i := 0; i < numRequests; i++ {
		computeReq := types.ComputeRequest{
			RequestID:   sha256.Sum256([]byte("test-request-id-batch-error")),
			Ciphertexts: [][]byte{[]byte("test-ciphertext")},
			PublicData:  []byte("test-public-data"),
		}

		hash := computeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*signerKeys[i], prefixedHash)

		execReq := types.SignedComputeRequest{
			ComputeRequest: computeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		executeRequests[i] = httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		recorders[i] = httptest.NewRecorder()
	}

	for i := 0; i < numRequests-1; i++ {
		go func(idx int) {
			host.handleExecute(recorders[idx], executeRequests[idx])
		}(i)
	}

	// Give time for the first two requests to be processed
	time.Sleep(100 * time.Millisecond)

	// No batch should be processed yet
	assert.Empty(t, mockTransport.requests)

	// Submit the third request which should trigger processing
	host.handleExecute(recorders[numRequests-1], executeRequests[numRequests-1])

	// Assert that the batch was processed.
	success := false
	for range 100 {
		if len(mockTransport.requests) == 1 {
			success = true
			for _, rec := range recorders {
				if rec.Code != http.StatusInternalServerError || len(rec.Body.String()) == 0 {
					success = false
				}
			}
			if success {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.True(t, success, "batch request was not sent within timeout")

	// Check that all client requests received the specific error
	for i, rec := range recorders {
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "Response recorder %d has unexpected status code", i)
		assert.Contains(t, rec.Body.String(), specificError.Error(), "Response %d doesn't contain the specific error message", i)
	}

	// Test a different error to ensure error propagation is generic.
	mockTransport.err = errors.New("failed to communicate with enclave: connection refused")
	mockTransport.requests = nil // Reset requests

	newSignerKeys := make([]*ed25519.PrivateKey, numRequests)
	newSigners := make([][]byte, numRequests)

	for i := 0; i < numRequests; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		newSignerKeys[i] = &privKey
		newSigners[i] = pubKey
	}

	newConfig := types.EnclaveConfig{
		Signers:         newSigners,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	newHost := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})
	newHost.config = newConfig

	newComputeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-id-batch-error")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	hash := newComputeReq.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	signature := ed25519.Sign(*newSignerKeys[0], prefixedHash)

	newExecReq := types.SignedComputeRequest{
		ComputeRequest: newComputeReq,
		Signature:      signature,
	}

	newReqBytes := util.MustMarshal(t, newExecReq)
	newRecorder := httptest.NewRecorder()
	newReq := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(newReqBytes))

	for i := 1; i < 3; i++ {
		hash := newComputeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*newSignerKeys[i], prefixedHash)

		execReq := types.SignedComputeRequest{
			ComputeRequest: newComputeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		r := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		w := httptest.NewRecorder()
		go newHost.handleExecute(w, r)
	}

	time.Sleep(100 * time.Millisecond)

	// This should trigger batch processing.
	newHost.handleExecute(newRecorder, newReq)

	// Assert that the batch was processed.
	success = false
	for range 100 {
		if len(mockTransport.requests) == 1 {
			success = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.True(t, success, "batch request was not sent within timeout")

	// Verify that the new error is also properly propagated
	assert.Equal(t, http.StatusInternalServerError, newRecorder.Code)
	assert.Contains(t, newRecorder.Body.String(), "failed to communicate with enclave: connection refused")
}

// TestHandleExecuteWithQuorumTimeoutEarlyExit verifies that when quorum is reached and batch
// processes successfully, the timeout goroutine exits early without waiting for the full timeout.
func TestHandleExecuteWithQuorumTimeoutEarlyExit(t *testing.T) {
	// Set a long timeout - if the test takes anywhere near this long, early exit isn't working
	originalTimeout := *quorumTimeout
	*quorumTimeout = 5 * time.Second
	defer func() { *quorumTimeout = originalTimeout }()

	const numSigners = 3
	signerKeys := make([]*ed25519.PrivateKey, numSigners)
	signers := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	mockExecResponse := types.ExecuteResponse{
		RequestID:   sha256.Sum256([]byte("test-request-early-exit")),
		Output:      []byte("test-output"),
		Attestation: []byte("test-attestation"),
	}
	respBytes := util.MustMarshal(t, mockExecResponse)

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	mockTransport := &mockRoundTripper{response: mockResp}
	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-early-exit")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	// Submit all 3 requests to reach quorum
	recorders := make([]*httptest.ResponseRecorder, numSigners)
	done := make([]chan struct{}, numSigners)

	startTime := time.Now()

	for i := 0; i < numSigners; i++ {
		hash := computeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*signerKeys[i], prefixedHash)

		execReq := types.SignedComputeRequest{
			ComputeRequest: computeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		req := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		recorders[i] = httptest.NewRecorder()
		done[i] = make(chan struct{})

		go func(idx int, r *http.Request) {
			host.handleExecute(recorders[idx], r)
			close(done[idx])
		}(i, req)
	}

	// Wait for all requests to complete
	for i := 0; i < numSigners; i++ {
		select {
		case <-done[i]:
		case <-time.After(2 * time.Second):
			t.Fatalf("Request %d did not complete within expected time", i)
		}
	}

	elapsed := time.Since(startTime)

	// Verify the test completed quickly (well under the 5 second timeout)
	assert.Less(t, elapsed, 1*time.Second, "Test should complete quickly due to early exit, not wait for full timeout")

	// Verify all requests succeeded
	for i, rec := range recorders {
		assert.Equal(t, http.StatusOK, rec.Code, "Request %d should have succeeded", i)
	}

	// Verify request was sent to enclave
	assert.Len(t, mockTransport.requests, 1, "One batch request should be sent to enclave")
}

// TestHandleExecuteWithSlowProcessingNoTimeout verifies that when quorum is reached but
// processing takes longer than the timeout, the batch still succeeds (processingRequest flag works).
func TestHandleExecuteWithSlowProcessingNoTimeout(t *testing.T) {
	// Set a very short timeout that would fire during processing
	originalTimeout := *quorumTimeout
	*quorumTimeout = 100 * time.Millisecond
	defer func() { *quorumTimeout = originalTimeout }()

	const numSigners = 3
	signerKeys := make([]*ed25519.PrivateKey, numSigners)
	signers := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	mockExecResponse := types.ExecuteResponse{
		RequestID:   sha256.Sum256([]byte("test-request-slow-processing")),
		Output:      []byte("test-output"),
		Attestation: []byte("test-attestation"),
	}
	respBytes := util.MustMarshal(t, mockExecResponse)

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	// Create a slow transport that takes longer than the timeout
	slowTransport := &mockRoundTripper{
		response: mockResp,
		delay:    300 * time.Millisecond, // Longer than the 100ms timeout
	}

	host := NewHostServer(context.Background(), &http.Client{Transport: slowTransport})
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-slow-processing")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	// Submit all 3 requests to reach quorum
	recorders := make([]*httptest.ResponseRecorder, numSigners)
	done := make([]chan struct{}, numSigners)

	for i := 0; i < numSigners; i++ {
		hash := computeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*signerKeys[i], prefixedHash)

		execReq := types.SignedComputeRequest{
			ComputeRequest: computeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		req := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		recorders[i] = httptest.NewRecorder()
		done[i] = make(chan struct{})

		go func(idx int, r *http.Request) {
			host.handleExecute(recorders[idx], r)
			close(done[idx])
		}(i, req)
	}

	// Wait for all requests to complete (should succeed despite timeout firing during processing)
	for i := 0; i < numSigners; i++ {
		select {
		case <-done[i]:
		case <-time.After(2 * time.Second):
			t.Fatalf("Request %d did not complete within expected time", i)
		}
	}

	// Verify all requests succeeded (not timed out due to processingRequest flag)
	for i, rec := range recorders {
		assert.Equal(t, http.StatusOK, rec.Code, "Request %d should have succeeded despite slow processing", i)
		assert.NotContains(t, rec.Body.String(), types.ErrQuorumTimeout, "Request %d should not contain timeout error", i)
	}

	// Verify request was sent to enclave
	assert.Len(t, slowTransport.requests, 1, "One batch request should be sent to enclave")
}

// TestHandleExecuteWithQuorumTimeout verifies that requests timeout when quorum is not reached
func TestHandleExecuteWithQuorumTimeout(t *testing.T) {
	// Save the original timeout and set a short one for the test
	originalTimeout := *quorumTimeout
	*quorumTimeout = 500 * time.Millisecond
	defer func() { *quorumTimeout = originalTimeout }()

	// Create 3 signers but set F=2 so we need 3 requests for quorum
	const numSigners = 3
	signerKeys := make([]*ed25519.PrivateKey, numSigners)
	signers := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	mockTransport := &mockRoundTripper{}
	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-quorum-timeout")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	// Only submit 2 requests (need 3 for quorum)
	recorders := make([]*httptest.ResponseRecorder, 2)
	done := make([]chan struct{}, 2)

	for i := 0; i < 2; i++ {
		hash := computeReq.Hash()
		prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
		signature := ed25519.Sign(*signerKeys[i], prefixedHash)

		execReq := types.SignedComputeRequest{
			ComputeRequest: computeReq,
			Signature:      signature,
		}

		reqBytes := util.MustMarshal(t, execReq)
		req := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
		recorders[i] = httptest.NewRecorder()
		done[i] = make(chan struct{})

		go func(idx int, r *http.Request) {
			host.handleExecute(recorders[idx], r)
			close(done[idx])
		}(i, req)
	}

	// Wait for both requests to complete (should timeout)
	for i := 0; i < 2; i++ {
		select {
		case <-done[i]:
		case <-time.After(2 * time.Second):
			t.Fatalf("Request %d did not complete within expected time", i)
		}
	}

	// Verify that no requests were sent to the enclave
	assert.Empty(t, mockTransport.requests, "No requests should be sent to enclave when quorum not reached")

	// Verify both requests received a quorum timeout error
	for i, rec := range recorders {
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "Request %d should have failed", i)
		assert.Contains(t, rec.Body.String(), types.ErrQuorumTimeout, "Request %d should contain quorum_timeout error", i)
		assert.Contains(t, rec.Body.String(), "received 2 of 3", "Request %d should indicate received vs required signatures", i)
	}
}

// TestHandleExecuteWithInvalidSigner verifies that requests signed by unauthorized keys are rejected
// and that duplicate signatures from the same signer are detected
func TestHandleExecuteWithInvalidSigner(t *testing.T) {
	// Generate authorized signers - need 3 for threshold = 2*1+1 = 3
	const numSigners = 3
	signerKeys := make([]*ed25519.PrivateKey, numSigners)
	signers := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	// Generate an unauthorized key
	_, unauthorizedKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               1,
		F:               2, // threshold = F+1 = 3
	}

	mockTransport := &mockRoundTripper{}
	host := NewHostServer(context.Background(), &http.Client{Transport: mockTransport})
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-id")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}
	hash := computeReq.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	signature := ed25519.Sign(unauthorizedKey, prefixedHash)

	execReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      signature,
	}

	reqBytes := util.MustMarshal(t, execReq)
	request := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
	recorder := httptest.NewRecorder()

	host.handleExecute(recorder, request)

	// Verify that the request signed by an unauthorized signer was rejected with a signer error.
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "signature not from any allowed signer")

	// Verify that no requests were forwarded to the enclave.
	assert.Empty(t, mockTransport.requests)

	mockExecResponse := types.ExecuteResponse{
		RequestID:   computeReq.RequestID,
		Output:      []byte("test-outputs"),
		Attestation: []byte("test-attestation"),
	}
	respBytes := util.MustMarshal(t, mockExecResponse)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	mockTransport.response = mockResp

	// Create the first valid request from an authorized signer.
	prefixedHash = types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	authorizedSignature := ed25519.Sign(*signerKeys[0], prefixedHash)

	authorizedExecReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      authorizedSignature,
	}

	authorizedReqBytes := util.MustMarshal(t, authorizedExecReq)
	authorizedRequest := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(authorizedReqBytes))
	authorizedRecorder := httptest.NewRecorder()

	// Create a duplicate request with the same signer.
	duplicateRequest := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(authorizedReqBytes))
	duplicateRecorder := httptest.NewRecorder()

	// Submit the first request async as to not block the test.
	done := make(chan struct{})
	go func() {
		host.handleExecute(authorizedRecorder, authorizedRequest)
		close(done)
	}()

	// Wait for the first request to be processed and queued, but not completed.
	var firstRequestQueued bool
	for i := 0; i < 50; i++ {
		host.processRequestMutex.Lock()
		requestHash := authorizedExecReq.Hash()
		_, firstRequestQueued = host.pendingRequestsCache.Get(requestHash)
		host.processRequestMutex.Unlock()

		if firstRequestQueued {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	require.True(t, firstRequestQueued, "First request was not queued within expected time")

	// Submit a duplicate request from the same signer.
	// With idempotent behavior, this should subscribe to the batch result
	// instead of being rejected.
	duplicateDone := make(chan struct{})
	go func() {
		host.handleExecute(duplicateRecorder, duplicateRequest)
		close(duplicateDone)
	}()

	// Wait for the duplicate to be added as a subscriber.
	time.Sleep(50 * time.Millisecond)

	// Create a request from the second authorized signer.
	prefixedHash = types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	secondSignature := ed25519.Sign(*signerKeys[1], prefixedHash)

	secondExecReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      secondSignature,
	}

	secondReqBytes := util.MustMarshal(t, secondExecReq)
	secondRequest := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(secondReqBytes))
	secondRecorder := httptest.NewRecorder()

	// Submit second request async
	done2 := make(chan struct{})
	go func() {
		host.handleExecute(secondRecorder, secondRequest)
		close(done2)
	}()

	// Wait for the second request to be queued
	time.Sleep(50 * time.Millisecond)

	// Create a request from the third authorized signer to complete the batch and reach quorum.
	prefixedHash = types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	thirdSignature := ed25519.Sign(*signerKeys[2], prefixedHash)

	thirdExecReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      thirdSignature,
	}

	thirdReqBytes := util.MustMarshal(t, thirdExecReq)
	thirdRequest := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(thirdReqBytes))
	thirdRecorder := httptest.NewRecorder()

	host.handleExecute(thirdRecorder, thirdRequest)

	// Wait for all requests to complete.
	<-done
	<-done2
	<-duplicateDone

	// Verify all authorized requests were processed successfully,
	// including the duplicate signer who subscribed to the batch result.
	assert.Equal(t, http.StatusOK, authorizedRecorder.Code)
	assert.Equal(t, http.StatusOK, duplicateRecorder.Code)
	assert.Equal(t, http.StatusOK, secondRecorder.Code)
	assert.Equal(t, http.StatusOK, thirdRecorder.Code)

	// Verify that a request was sent to the enclave.
	assert.Equal(t, 1, len(mockTransport.requests))

	// Verify the batch contains only the three unique valid signatures (not the duplicate).
	var enclaveReqs []types.SignedComputeRequest
	bodyBytes, err := io.ReadAll(mockTransport.requests[0].Body)
	require.NoError(t, err)
	err = json.Unmarshal(bodyBytes, &enclaveReqs)
	require.NoError(t, err)
	assert.Equal(t, 3, len(enclaveReqs))
}

// TestHandleQuorumTimeoutGracefulShutdown verifies that when the context is cancelled
// (simulating server shutdown), the timeout goroutine exits immediately.
func TestHandleQuorumTimeoutGracefulShutdown(t *testing.T) {
	// Set a very long timeout - if shutdown doesn't work, the test would hang
	originalTimeout := *quorumTimeout
	*quorumTimeout = 10 * time.Second
	defer func() { *quorumTimeout = originalTimeout }()

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	const numSigners = 3
	signerKeys := make([]*ed25519.PrivateKey, numSigners)
	signers := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signerKeys[i] = &privKey
		signers[i] = pubKey
	}

	config := types.EnclaveConfig{
		Signers:         signers,
		MasterPublicKey: []byte("master-public-key"),
		T:               2,
		F:               2, // threshold = F+1 = 3
	}

	mockTransport := &mockRoundTripper{}
	host := NewHostServer(ctx, &http.Client{Transport: mockTransport})
	host.config = config

	computeReq := types.ComputeRequest{
		RequestID:   sha256.Sum256([]byte("test-request-shutdown")),
		Ciphertexts: [][]byte{[]byte("test-ciphertext")},
		PublicData:  []byte("test-public-data"),
	}

	// Submit only 1 request (not enough for quorum)
	hash := computeReq.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	signature := ed25519.Sign(*signerKeys[0], prefixedHash)

	execReq := types.SignedComputeRequest{
		ComputeRequest: computeReq,
		Signature:      signature,
	}

	reqBytes := util.MustMarshal(t, execReq)
	req := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewReader(reqBytes))
	recorder := httptest.NewRecorder()

	// Submit the request in a goroutine - it will block waiting for quorum
	done := make(chan struct{})
	go func() {
		host.handleExecute(recorder, req)
		close(done)
	}()

	// Wait for the request to be queued
	time.Sleep(50 * time.Millisecond)

	startTime := time.Now()

	// Cancel the context to simulate shutdown
	cancel()

	// The request should fail relatively quickly due to context cancellation
	// We give it 1 second which is much less than the 10 second timeout
	select {
	case <-done:
		elapsed := time.Since(startTime)
		// Should complete much faster than the 10 second timeout
		assert.Less(t, elapsed, 2*time.Second, "Request should complete quickly after context cancellation")
	case <-time.After(3 * time.Second):
		t.Fatal("Request did not complete within expected time after context cancellation")
	}
}
