package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// mockAttestor returns the input data as the "attestation document" so tests can
// verify the correct hash was attested without needing real Nitro hardware.
type mockAttestor struct{}

func (m *mockAttestor) CreateAttestation(data []byte) ([]byte, error) {
	return data, nil
}

func TestSendRequest_RejectsOversizeResponse(t *testing.T) {
	// A malicious/buggy gateway returning a body larger than the cap must be
	// rejected before the whole body is buffered, not OOM the enclave. [CL112-07]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, types.MaxEnclaveResponseBodyBytes+1))
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, nil)
	_, err := client.SendRequest(context.Background(), "test_method", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for oversize response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want it to mention 'exceeds limit'", err.Error())
	}
}

func TestNewGatewayClient_SetsTimeout(t *testing.T) {
	client := NewGatewayClient("https://gateway.example", nil)
	if client.httpClient.Timeout != types.DefaultGatewayRequestTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", client.httpClient.Timeout, types.DefaultGatewayRequestTimeout)
	}
}

func TestNewGatewayClient_WithTimeout(t *testing.T) {
	client := NewGatewayClient("https://gateway.example", nil, WithTimeout(45*time.Second))
	if client.httpClient.Timeout != 45*time.Second {
		t.Errorf("httpClient.Timeout = %v, want %v", client.httpClient.Timeout, 45*time.Second)
	}
}

func TestSendRequest_HappyPath(t *testing.T) {
	want := json.RawMessage(`{"foo":"bar"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		req, err := jsonrpc2.DecodeRequest[json.RawMessage](body, "")
		if err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if req.Method != "test_method" {
			t.Errorf("method = %q, want %q", req.Method, "test_method")
		}

		result := want
		resp := jsonrpc2.Response[json.RawMessage]{
			Version: jsonrpc2.JsonRpcVersion,
			ID:      req.ID,
			Result:  &result,
		}
		respBytes, _ := jsonrpc2.EncodeResponse(&resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, nil)
	got, err := client.SendRequest(context.Background(), "test_method", json.RawMessage(`{"key":"val"}`))
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	var gotVal, wantVal any
	_ = json.Unmarshal(got, &gotVal)
	_ = json.Unmarshal(want, &wantVal)
	if gotJSON, _ := json.Marshal(gotVal); string(gotJSON) != string(want) {
		t.Errorf("result = %s, want %s", got, want)
	}
}

func TestSendRequest_RPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := jsonrpc2.DecodeRequest[json.RawMessage](body, "")

		resp := jsonrpc2.Response[json.RawMessage]{
			Version: jsonrpc2.JsonRpcVersion,
			ID:      req.ID,
			Error:   &jsonrpc2.WireError{Code: jsonrpc2.ErrInvalidRequest, Message: "invalid request"},
		}
		respBytes, _ := jsonrpc2.EncodeResponse(&resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, nil)
	_, err := client.SendRequest(context.Background(), "bad_method", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "JSON-RPC error -32600: invalid request" {
		t.Errorf("error = %q, want JSON-RPC error message", got)
	}
}

func TestSendRequest_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, nil)
	_, err := client.SendRequest(context.Background(), "method", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestSendRequest_AttestationHeader(t *testing.T) {
	att := &mockAttestor{}
	var receivedHeader string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get(attestationHeader)
		receivedBody, _ = io.ReadAll(r.Body)

		req, _ := jsonrpc2.DecodeRequest[json.RawMessage](receivedBody, "")
		result := json.RawMessage(`null`)
		resp := jsonrpc2.Response[json.RawMessage]{
			Version: jsonrpc2.JsonRpcVersion,
			ID:      req.ID,
			Result:  &result,
		}
		respBytes, _ := jsonrpc2.EncodeResponse(&resp)
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, att)
	_, err := client.SendRequest(context.Background(), "attested_method", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	if receivedHeader == "" {
		t.Fatal("expected X-Attestation-Document header, got empty")
	}

	// The mock attestor returns the hash as-is, so decoding the header should
	// give us SHA256(DomainSeparator + "\nGatewayRequest\n" + body).
	decoded, err := base64.StdEncoding.DecodeString(receivedHeader)
	if err != nil {
		t.Fatalf("decoding attestation header: %v", err)
	}

	h := sha256.New()
	h.Write([]byte(types.DomainSeparator))
	h.Write([]byte("\nGatewayRequest\n"))
	h.Write(receivedBody)
	expectedHash := h.Sum(nil)

	if string(decoded) != string(expectedHash) {
		t.Errorf("attestation hash mismatch:\n  got:  %x\n  want: %x", decoded, expectedHash)
	}
}

func TestSendRequest_NoAttestor(t *testing.T) {
	var receivedHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get(attestationHeader)

		body, _ := io.ReadAll(r.Body)
		req, _ := jsonrpc2.DecodeRequest[json.RawMessage](body, "")
		result := json.RawMessage(`null`)
		resp := jsonrpc2.Response[json.RawMessage]{
			Version: jsonrpc2.JsonRpcVersion,
			ID:      req.ID,
			Result:  &result,
		}
		respBytes, _ := jsonrpc2.EncodeResponse(&resp)
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	client := NewGatewayClient(srv.URL, nil)
	_, err := client.SendRequest(context.Background(), "method", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	if receivedHeader != "" {
		t.Errorf("expected no attestation header, got %q", receivedHeader)
	}
}

func TestSendRequest_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewGatewayClient(srv.URL, nil)
	_, err := client.SendRequest(ctx, "method", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
