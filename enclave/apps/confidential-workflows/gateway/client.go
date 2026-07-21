package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"

	"github.com/smartcontractkit/confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

const attestationHeader = "X-Attestation-Document"

type GatewayClient struct {
	gatewayURLs []string          // one or more; round-robined per request
	attestor    attestor.Attestor // nil = skip attestation (local testing)
	httpClient  *http.Client
	cursor      atomic.Uint64 // advances per SendRequest to pick the starting URL
}

// Option configures a GatewayClient.
type Option func(*GatewayClient)

// WithTimeout overrides the default HTTP client timeout for gateway requests.
// The timeout should not exceed the enclave request timeout, since the gateway
// call is nested inside the enclave's own request lifecycle.
func WithTimeout(d time.Duration) Option {
	return func(c *GatewayClient) {
		c.httpClient.Timeout = d
	}
}

// NewGatewayClient builds a client over one or more gateway endpoints.
// gatewayURLs is a comma-separated list; SendRequest round-robins across the
// entries and fails over to the next on a transport/proxy error. A single URL
// (no comma) behaves exactly like before.
func NewGatewayClient(gatewayURLs string, att attestor.Attestor, opts ...Option) *GatewayClient {
	c := &GatewayClient{
		gatewayURLs: parseGatewayURLs(gatewayURLs),
		attestor:    att,
		httpClient:  &http.Client{Timeout: types.DefaultGatewayRequestTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// parseGatewayURLs splits a comma-separated list, trimming whitespace and
// dropping empty entries.
func parseGatewayURLs(raw string) []string {
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			urls = append(urls, p)
		}
	}
	return urls
}

// SendRequest sends a JSON-RPC 2.0 request to the Gateway and returns the result.
// It attests the request body and attaches the attestation as an HTTP header.
// params is json.RawMessage so callers marshal their own typed request structs.
//
// When multiple gateway URLs are configured, it round-robins across them (the
// starting URL advances per call) and, within a call, fails over to the next URL
// on a transport or proxy-level error (connection failure, HTTP 5xx without a
// JSON-RPC body). A well-formed JSON-RPC error (e.g. relay quorum unreachable)
// means the relay answered, so it is returned immediately without failover, as
// is any HTTP 4xx. The request body, JSON-RPC id, and attestation are built once
// and reused across attempts.
func (c *GatewayClient) SendRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if len(c.gatewayURLs) == 0 {
		return nil, fmt.Errorf("no gateway URLs configured")
	}

	id, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("generating request ID: %w", err)
	}

	req := jsonrpc2.Request[json.RawMessage]{
		Version: jsonrpc2.JsonRpcVersion,
		ID:      id,
		Method:  method,
		Params:  &params,
	}

	body, err := jsonrpc2.EncodeRequest(&req)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	var attHeader string
	if c.attestor != nil {
		hash := hashRequestBody(body)
		doc, err := c.attestor.CreateAttestation(hash)
		if err != nil {
			return nil, fmt.Errorf("creating attestation: %w", err)
		}
		attHeader = base64.StdEncoding.EncodeToString(doc)
	}

	n := len(c.gatewayURLs)
	start := int(c.cursor.Add(1) - 1)
	var attemptErrs []error
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		url := c.gatewayURLs[(start+i)%n]
		result, retryable, err := c.sendOne(ctx, url, body, attHeader)
		if err == nil {
			return result, nil
		}
		if !retryable {
			return nil, err
		}
		attemptErrs = append(attemptErrs, fmt.Errorf("gateway %s: %w", url, err))
		// Pause before failing over to give a briefly-unhealthy gateway a
		// moment to recover; skip the wait after the final attempt.
		if i < n-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(types.GatewayFailoverDelay):
			}
		}
	}
	return nil, fmt.Errorf("all %d gateways failed: %w", n, errors.Join(attemptErrs...))
}

// sendOne performs a single POST to one gateway URL. It returns the JSON-RPC
// result on success. The retryable flag tells SendRequest whether to fail over
// to the next URL: true for transport/proxy failures (the gateway itself is at
// fault), false for a terminal answer (a JSON-RPC error from the relay, an HTTP
// 4xx, or a malformed/oversize response).
func (c *GatewayClient) sendOne(ctx context.Context, url string, body []byte, attHeader string) (json.RawMessage, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if attHeader != "" {
		httpReq.Header.Set(attestationHeader, attHeader)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, true, fmt.Errorf("sending request: %w", err)
	}
	defer util.SafeClose(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(respBody)) > types.MaxEnclaveResponseBodyBytes {
		return nil, false, fmt.Errorf("gateway response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
	}

	// A well-formed JSON-RPC error means the relay answered (e.g. quorum
	// unreachable). That is a terminal result, not the gateway's transport
	// fault, so surface it directly without failing over.
	rpcResp, decErr := jsonrpc2.DecodeResponse[json.RawMessage](respBody)
	if decErr == nil && rpcResp.Error != nil {
		return nil, false, fmt.Errorf("JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if resp.StatusCode != http.StatusOK {
		// No JSON-RPC body: a transport/proxy failure (e.g. Envoy 5xx). 5xx is
		// transient so fail over; 4xx is deterministic so treat as terminal.
		retryable := resp.StatusCode >= 500
		return nil, retryable, fmt.Errorf("gateway returned HTTP %d: %s", resp.StatusCode, respBody)
	}

	if decErr != nil {
		return nil, false, fmt.Errorf("unmarshalling response: %w", decErr)
	}
	if rpcResp.Result == nil {
		return nil, false, nil
	}
	return *rpcResp.Result, false, nil
}

// hashRequestBody produces the SHA-256 hash used as attestation UserData.
// Format follows the existing domain-separated hashing pattern from types.go.
func hashRequestBody(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(types.DomainSeparator))
	h.Write([]byte("\nGatewayRequest\n"))
	h.Write(body)
	return h.Sum(nil)
}

// newUUID generates a random UUID v4 string.
func newUUID() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}
