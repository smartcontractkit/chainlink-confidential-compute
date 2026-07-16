package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"

	"github.com/smartcontractkit/confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

const attestationHeader = "X-Attestation-Document"

type GatewayClient struct {
	gatewayURL string
	attestor   attestor.Attestor // nil = skip attestation (local testing)
	httpClient *http.Client
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

func NewGatewayClient(gatewayURL string, att attestor.Attestor, opts ...Option) *GatewayClient {
	c := &GatewayClient{
		gatewayURL: gatewayURL,
		attestor:   att,
		httpClient: &http.Client{Timeout: types.DefaultGatewayRequestTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SendRequest sends a JSON-RPC 2.0 request to the Gateway and returns the result.
// It attests the request body and attaches the attestation as an HTTP header.
// params is json.RawMessage so callers marshal their own typed request structs.
func (c *GatewayClient) SendRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.gatewayURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if c.attestor != nil {
		hash := hashRequestBody(body)
		doc, err := c.attestor.CreateAttestation(hash)
		if err != nil {
			return nil, fmt.Errorf("creating attestation: %w", err)
		}
		httpReq.Header.Set(attestationHeader, base64.StdEncoding.EncodeToString(doc))
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer util.SafeClose(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, types.MaxEnclaveResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(respBody)) > types.MaxEnclaveResponseBodyBytes {
		return nil, fmt.Errorf("gateway response body exceeds limit %d bytes", types.MaxEnclaveResponseBodyBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d: %s", resp.StatusCode, respBody)
	}

	rpcResp, err := jsonrpc2.DecodeResponse[json.RawMessage](respBody)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return nil, nil
	}

	return *rpcResp.Result, nil
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
