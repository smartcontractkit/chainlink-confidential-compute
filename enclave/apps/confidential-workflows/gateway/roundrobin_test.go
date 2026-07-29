package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"
)

// resultHandler echoes a JSON-RPC success result and counts hits.
func resultHandler(hits *atomic.Int32, result json.RawMessage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, _ := jsonrpc2.DecodeRequest[json.RawMessage](body, "")
		res := result
		resp := jsonrpc2.Response[json.RawMessage]{Version: jsonrpc2.JsonRpcVersion, ID: req.ID, Result: &res}
		b, _ := jsonrpc2.EncodeResponse(&resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}
}

// jsonrpcErrorHandler returns an HTTP status with a well-formed JSON-RPC error
// body (as the real gateway does for "relay quorum unreachable") and counts hits.
func jsonrpcErrorHandler(hits *atomic.Int32, status int, code int64, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, _ := jsonrpc2.DecodeRequest[json.RawMessage](body, "")
		resp := jsonrpc2.Response[json.RawMessage]{Version: jsonrpc2.JsonRpcVersion, ID: req.ID, Error: &jsonrpc2.WireError{Code: code, Message: msg}}
		b, _ := jsonrpc2.EncodeResponse(&resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	}
}

// statusHandler returns a bare HTTP status with a plaintext body (Envoy-style
// proxy error, no JSON-RPC envelope) and counts hits.
func statusHandler(hits *atomic.Int32, status int, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, msg, status)
	}
}

func urls(srvs ...*httptest.Server) string {
	u := make([]string, len(srvs))
	for i, s := range srvs {
		u[i] = s.URL
	}
	return strings.Join(u, ",")
}

// A transport/proxy 5xx on the first gateway fails over to the next.
func TestSendRequest_FailsOverOn5xx(t *testing.T) {
	var badHits, goodHits atomic.Int32
	bad := httptest.NewServer(statusHandler(&badHits, http.StatusServiceUnavailable, "upstream connect error"))
	defer bad.Close()
	want := json.RawMessage(`{"ok":true}`)
	good := httptest.NewServer(resultHandler(&goodHits, want))
	defer good.Close()

	// cursor starts at 0, so the first call starts at index 0 (the bad server).
	client := NewGatewayClient(urls(bad, good), nil)
	got, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("result = %s, want %s", got, want)
	}
	if badHits.Load() != 1 || goodHits.Load() != 1 {
		t.Errorf("hits: bad=%d good=%d, want 1 and 1 (should fail over)", badHits.Load(), goodHits.Load())
	}
}

// A JSON-RPC error (relay quorum unreachable, HTTP 500 + error body) is the
// relay's answer, not a gateway fault: return it, do NOT fail over.
func TestSendRequest_QuorumErrorNotRetried(t *testing.T) {
	var quorumHits, goodHits atomic.Int32
	quorum := httptest.NewServer(jsonrpcErrorHandler(&quorumHits, http.StatusInternalServerError, jsonrpc2.ErrInternal, "relay quorum unreachable"))
	defer quorum.Close()
	good := httptest.NewServer(resultHandler(&goodHits, json.RawMessage(`{"ok":true}`)))
	defer good.Close()

	client := NewGatewayClient(urls(quorum, good), nil)
	_, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected JSON-RPC error, got nil")
	}
	if !strings.Contains(err.Error(), "relay quorum unreachable") {
		t.Errorf("error = %q, want it to mention the quorum error", err.Error())
	}
	if quorumHits.Load() != 1 {
		t.Errorf("quorum server hits = %d, want 1", quorumHits.Load())
	}
	if goodHits.Load() != 0 {
		t.Errorf("second gateway hits = %d, want 0 (must not fail over on a relay answer)", goodHits.Load())
	}
}

// A 4xx is deterministic: return it, do NOT fail over.
func TestSendRequest_4xxNotRetried(t *testing.T) {
	var badHits, goodHits atomic.Int32
	bad := httptest.NewServer(statusHandler(&badHits, http.StatusBadRequest, "bad request"))
	defer bad.Close()
	good := httptest.NewServer(resultHandler(&goodHits, json.RawMessage(`{"ok":true}`)))
	defer good.Close()

	client := NewGatewayClient(urls(bad, good), nil)
	_, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for 4xx, got nil")
	}
	if goodHits.Load() != 0 {
		t.Errorf("second gateway hits = %d, want 0 (4xx is terminal)", goodHits.Load())
	}
}

// When every gateway fails with a transport/proxy error, all are tried and the
// joined error names them.
func TestSendRequest_AllGatewaysFail(t *testing.T) {
	var aHits, bHits atomic.Int32
	a := httptest.NewServer(statusHandler(&aHits, http.StatusBadGateway, "boom"))
	defer a.Close()
	b := httptest.NewServer(statusHandler(&bHits, http.StatusServiceUnavailable, "boom"))
	defer b.Close()

	client := NewGatewayClient(urls(a, b), nil)
	_, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error when all gateways fail")
	}
	if !strings.Contains(err.Error(), "all 2 gateways failed") {
		t.Errorf("error = %q, want it to mention 'all 2 gateways failed'", err.Error())
	}
	if aHits.Load() != 1 || bHits.Load() != 1 {
		t.Errorf("hits: a=%d b=%d, want both tried once", aHits.Load(), bHits.Load())
	}
}

// Successive calls to healthy gateways round-robin the starting URL, so load
// spreads: two calls over two healthy gateways hit each exactly once.
func TestSendRequest_RoundRobinsStart(t *testing.T) {
	var aHits, bHits atomic.Int32
	a := httptest.NewServer(resultHandler(&aHits, json.RawMessage(`{"ok":true}`)))
	defer a.Close()
	b := httptest.NewServer(resultHandler(&bHits, json.RawMessage(`{"ok":true}`)))
	defer b.Close()

	client := NewGatewayClient(urls(a, b), nil)
	for i := 0; i < 2; i++ {
		if _, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("SendRequest #%d: %v", i, err)
		}
	}
	if aHits.Load() != 1 || bHits.Load() != 1 {
		t.Errorf("hits: a=%d b=%d, want 1 and 1 (round-robin start)", aHits.Load(), bHits.Load())
	}
}

func TestSendRequest_NoGatewaysConfigured(t *testing.T) {
	client := NewGatewayClient("", nil)
	_, err := client.SendRequest(context.Background(), "m", json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "no gateway URLs") {
		t.Errorf("err = %v, want 'no gateway URLs configured'", err)
	}
}

func TestParseGatewayURLs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{",", nil},
	}
	for _, tc := range cases {
		got := parseGatewayURLs(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseGatewayURLs(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseGatewayURLs(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
