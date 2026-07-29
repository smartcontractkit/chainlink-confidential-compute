package util

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
)

func MethodUsesBody(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func MustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	bytes, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes
}

func SafeClose(resp *http.Response) {
	if resp == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		log.Printf("Failed to close response body: %v", err)
	}
}

func SetNodeConfig(ctx context.Context, node types.Enclave, reqBody types.ConfigRequest, httpClient *http.Client) (*types.SetConfigResponse, error) {
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", node.EnclaveURL+types.SetConfigPath, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer SafeClose(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var configResp types.SetConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&configResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &configResp, nil
}

func SetAuthHeader(enclave types.Enclave, httpReq *http.Request) error {
	if enclave.EnclaveAuthHeader != "" {
		headerComponents := strings.Split(enclave.EnclaveAuthHeader, ":")
		if len(headerComponents) != 2 {
			return fmt.Errorf("malformed enclave auth header for enclave %x: %s", enclave.EnclaveID, enclave.EnclaveAuthHeader)
		}
		httpReq.Header.Set(strings.TrimSpace(headerComponents[0]), strings.TrimSpace(headerComponents[1]))
	}
	return nil
}

func Ptr[T any](t T) *T { return &t }

func GetRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func GetConfidentialComputePayloadPrefix() string {
	return "CONFIDENTIAL_COMPUTE_PAYLOAD_"
}

func GetConfidentialComputeConfigUpdatePrefix() string {
	return "CONFIDENTIAL_COMPUTE_CONFIG_UPDATE_"
}
