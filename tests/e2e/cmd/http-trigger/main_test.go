package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	jsonrpc "github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"
	"github.com/smartcontractkit/chainlink-common/pkg/types/gateway"
	chainlinkutils "github.com/smartcontractkit/chainlink/v2/core/utils"
	"github.com/stretchr/testify/require"
)

const testWorkflowID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trigger.key")
	var out bytes.Buffer
	require.NoError(t, run([]string{"-init-key", "-key-file", path}, &out))
	key, err := crypto.LoadECDSA(path)
	require.NoError(t, err)
	require.Equal(t, strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())+"\n", out.String())
	require.NotContains(t, out.String(), hex.EncodeToString(crypto.FromECDSA(key)))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Error(t, run([]string{"-init-key", "-key-file", path}, &out))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, after)
	require.Error(t, run([]string{"-init-key", "-key-file", path, "-gateway", "https://example.com"}, &out))
	require.Error(t, run([]string{"-init-key", "-key-file", path, "-case", "redirect"}, &out))
}

func TestSendTrigger_SignedOnce(t *testing.T) {
	for _, caseName := range []string{"redirect", "certificate"} {
		t.Run(caseName, func(t *testing.T) {
			key, err := crypto.GenerateKey()
			require.NoError(t, err)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "application/jsonrpc", r.Header.Get("Content-Type"))
				var req jsonrpc.Request[json.RawMessage]
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				require.Equal(t, gateway.MethodWorkflowExecute, req.Method)
				claims, signer, err := chainlinkutils.VerifyRequestJWT(req.Auth, req)
				require.NoError(t, err)
				require.Equal(t, crypto.PubkeyToAddress(key.PublicKey), signer)
				require.NotEmpty(t, claims.ID)
				require.LessOrEqual(t, claims.ExpiresAt.Sub(claims.IssuedAt.Time), 5*time.Minute)
				var payload gateway.HTTPTriggerRequest
				require.NoError(t, json.Unmarshal(*req.Params, &payload))
				require.Equal(t, gateway.WorkflowSelector{WorkflowID: testWorkflowID}, payload.Workflow)
				require.JSONEq(t, `{"case":"`+caseName+`"}`, string(payload.Input))

				for _, altered := range []json.RawMessage{
					json.RawMessage(`{"workflow":{"workflowID":"different"},"input":{"case":"` + caseName + `"}}`),
					json.RawMessage(`{"workflow":{"workflowID":"` + testWorkflowID + `"},"input":{}}`),
				} {
					tampered := req
					tampered.Params = &altered
					_, _, err = chainlinkutils.VerifyRequestJWT(req.Auth, tampered)
					require.Error(t, err, "signature must bind both the workflow selector and input")
				}

				require.NoError(t, json.NewEncoder(w).Encode(jsonrpc.Response[gateway.HTTPTriggerResponse]{
					Version: jsonrpc.JsonRpcVersion, ID: req.ID,
					Result: &gateway.HTTPTriggerResponse{Status: gateway.HTTPTriggerStatusAccepted,
						WorkflowID: testWorkflowID, WorkflowExecutionID: "test-execution"},
				}))
			}))
			t.Cleanup(server.Close)
			result, err := sendTrigger(t.Context(), server.URL, "0x"+testWorkflowID, caseName, key, server.Client().Transport)
			require.NoError(t, err)
			require.Equal(t, "test-execution", result.WorkflowExecutionID)
			require.Equal(t, gateway.HTTPTriggerStatusAccepted, result.Status)
			require.EqualValues(t, 1, requests.Load())
		})
	}
}

func TestSendTrigger_RejectsWithoutRetry(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	var forwarded atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
	t.Cleanup(target.Close)
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, "fake-credential"},
		{"rate limited", 429, "fake-credential"},
		{"unavailable", 503, "fake-credential"},
		{"redirect", 307, "fake-credential"},
		{"malformed", 200, "fake-credential"},
		{"RPC error", 200, `{"jsonrpc":"2.0","id":"$ID","error":{"code":-32000,"message":"fake-credential"}}`},
		{"missing result", 200, `{"jsonrpc":"2.0","id":"$ID"}`},
		{"not accepted", 200, `{"jsonrpc":"2.0","id":"$ID","result":{"status":"REJECTED"}}`},
		{"wrong ID", 200, `{"jsonrpc":"2.0","id":"other","result":{"status":"ACCEPTED"}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				var req jsonrpc.Request[json.RawMessage]
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				w.Header().Set("Location", target.URL)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(strings.ReplaceAll(tt.body, "$ID", req.ID)))
			}))
			t.Cleanup(server.Close)
			result, err := sendTrigger(t.Context(), server.URL, testWorkflowID, "redirect", key, server.Client().Transport)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "fake-credential")
			require.Nil(t, result)
			require.EqualValues(t, 1, requests.Load())
		})
	}
	require.Zero(t, forwarded.Load(), "signed requests must not follow redirects")
}

func TestSendTrigger_RequiresHTTPSAndValidID(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	for _, endpoint := range []string{"", "http://example.com", "https://user:password@example.com", "https://example.com?token=secret", "https://example.com#secret"} {
		_, err := sendTrigger(t.Context(), endpoint, testWorkflowID, "redirect", key, nil)
		require.ErrorContains(t, err, "HTTPS URL")
	}
	_, err = sendTrigger(t.Context(), "https://example.com", "bad-id", "redirect", key, nil)
	require.ErrorContains(t, err, "32 bytes of hex")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = sendTrigger(ctx, "https://example.com", testWorkflowID, "redirect", key, nil)
	require.ErrorContains(t, err, "check execution history before retrying")
}

func TestSendTrigger_RejectsUntrustedTLS(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	_, err = sendTrigger(t.Context(), server.URL, testWorkflowID, "redirect", key, nil)
	require.ErrorContains(t, err, "trigger transport failed")
	require.Zero(t, requests.Load())
}

func TestSendTrigger_RequiresFixedCase(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	for _, caseName := range []string{"", "unknown", "https://example.com", "fake-secret"} {
		_, err := sendTrigger(t.Context(), server.URL, testWorkflowID, caseName, key, server.Client().Transport)
		require.EqualError(t, err, "case must be redirect or certificate")
	}
	require.Zero(t, requests.Load())
}
