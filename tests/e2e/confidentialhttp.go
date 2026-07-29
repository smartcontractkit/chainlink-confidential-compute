package tests

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	cctypes "github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

// aesKeyForEncryptionTest is a hex-encoded 32-byte AES-256 key used in e2e tests.
// The enclave hex-decodes this before using it for AES-GCM encryption.
var aesKeyForEncryptionTest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func getConfidentialHTTPSecrets() (names, values []string) {
	secretID := "testsecret" + strconv.Itoa(rand.Intn(10000))
	secretID2 := "alphasecret2" + strconv.Itoa(rand.Intn(10000))
	names = []string{secretID, secretID2, cctypes.AESGCMEncryptionKey}
	values = []string{"API123", "message", aesKeyForEncryptionTest}
	return names, values
}

// TriggerInput mirrors the workflow's TriggerInput type. It is sent as the
// "input" field of the HTTP trigger request (gateway_common.HTTPTriggerRequest).
type TriggerInput struct {
	URL                  string            `json:"url"`
	Method               string            `json:"method"`
	Body                 string            `json:"body,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	TemplatePublicValues map[string]string `json:"templatePublicValues,omitempty"`
	VaultSecrets         []VaultSecretRef  `json:"vaultSecrets,omitempty"`
	CustomRootCACertPEM  string            `json:"customRootCACertPem,omitempty"`
	EncryptOutput        bool              `json:"encryptOutput,omitempty"`
	TimeoutMs            int64             `json:"timeoutMs,omitempty"`
}

// VaultSecretRef identifies a secret in the Vault DON.
type VaultSecretRef struct {
	Key       string `json:"key"`
	Namespace string `json:"namespace,omitempty"`
	Owner     string `json:"owner,omitempty"`
}

// ResponseOutput mirrors the workflow's ResponseOutput type.
// The workflow POSTs this JSON to the recipient endpoint.
type ResponseOutput struct {
	StatusCode uint32            `json:"statusCode"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// getConfidentialHTTPTriggerInputs builds the trigger inputs that will be sent
// via the HTTP trigger gateway. Each input becomes a separate trigger invocation.
func getConfidentialHTTPTriggerInputs(secretNames []string, owner string) ([]json.RawMessage, error) {
	input1 := TriggerInput{
		URL:    "https://postman-echo.com/" + "post",
		Method: "POST",
		Body:   "{{.Message}}",
		TemplatePublicValues: map[string]string{
			"AuthType": "Bearer",
			"Message":  "test message",
		},
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": fmt.Sprintf("{{.AuthType}} {{.%s}}", secretNames[0]),
		},
		VaultSecrets: []VaultSecretRef{{
			Key:   secretNames[0],
			Owner: owner,
		}},
	}
	input1Bytes, err := json.Marshal(input1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal trigger input 1: %w", err)
	}

	rootCACert, err := util.GetRootCACertPEM("postman-echo.com")
	if err != nil {
		return nil, fmt.Errorf("failed to get root CA cert: %w", err)
	}

	input2 := TriggerInput{
		URL:    "https://postman-echo.com/" + "post",
		Method: "POST",
		Body:   fmt.Sprintf("test {{.%s}} {{.messageNum}}", secretNames[1]),
		TemplatePublicValues: map[string]string{
			"messageNum": "2",
		},
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": fmt.Sprintf("Bearer {{.%s}}", secretNames[0]),
		},
		CustomRootCACertPEM: string(rootCACert),
		EncryptOutput:       true,
		VaultSecrets: []VaultSecretRef{
			{Key: secretNames[0], Owner: owner},
			{Key: secretNames[1], Owner: owner},
			{Key: cctypes.AESGCMEncryptionKey, Owner: owner},
		},
	}
	input2Bytes, err := json.Marshal(input2)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal trigger input 2: %w", err)
	}

	return []json.RawMessage{input1Bytes, input2Bytes}, nil
}

// getConfidentialHTTPDNSFailureInput builds a trigger input with a non-existent
// hostname to exercise the NXDOMAIN handling path in the enclave app.
func getConfidentialHTTPDNSFailureInput(secretNames []string, owner string) (json.RawMessage, error) {
	input := TriggerInput{
		URL:    "https://this-host-definitely-does-not-exist-12345.example.invalid/api",
		Method: "GET",
		VaultSecrets: []VaultSecretRef{{
			Key:   secretNames[0],
			Owner: owner,
		}},
	}
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DNS failure input: %w", err)
	}
	return b, nil
}

// getConfidentialHTTPTimeoutInput builds a trigger input that targets a
// hanging server with a short timeout to exercise the upstream timeout path.
func getConfidentialHTTPTimeoutInput(hangingServerURL string, secretNames []string, owner string) (json.RawMessage, error) {
	input := TriggerInput{
		URL:       hangingServerURL,
		Method:    "GET",
		TimeoutMs: 500, // 500ms — the server will hang longer than this
		VaultSecrets: []VaultSecretRef{{
			Key:   secretNames[0],
			Owner: owner,
		}},
	}
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timeout input: %w", err)
	}
	return b, nil
}

// getConfidentialHTTPSSRFBlockedInput builds a trigger input that targets a
// private/internal address (the cloud metadata endpoint) to exercise the
// enclave's SSRF policy. The restricted client refuses the link-local IP at
// dial time, which the app converts to a 400 instead of a generic 500.
func getConfidentialHTTPSSRFBlockedInput(secretNames []string, owner string) (json.RawMessage, error) {
	input := TriggerInput{
		URL:    "https://169.254.169.254/latest/meta-data/",
		Method: "GET",
		VaultSecrets: []VaultSecretRef{{
			Key:   secretNames[0],
			Owner: owner,
		}},
	}
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SSRF blocked input: %w", err)
	}
	return b, nil
}

// validateSSRFBlockedResponse checks that the recipient received a 400 response
// with the sanitized network-policy message from the enclave.
func validateSSRFBlockedResponse(logger zerolog.Logger, bodies [][]byte) error {
	if len(bodies) == 0 {
		return fmt.Errorf("expected at least 1 recipient request for SSRF block, got 0")
	}
	for i, body := range bodies {
		var output ResponseOutput
		if err := json.Unmarshal(body, &output); err != nil {
			return fmt.Errorf("response %d: failed to unmarshal: %w", i, err)
		}
		if output.StatusCode != 400 {
			return fmt.Errorf("response %d: expected statusCode 400, got %d (body: %s)", i, output.StatusCode, output.Body)
		}
		if !strings.Contains(output.Body, "upstream request blocked by enclave network policy") {
			return fmt.Errorf("response %d: expected body to contain 'upstream request blocked by enclave network policy', got: %s", i, output.Body)
		}
		logger.Info().Msgf("SSRF blocked response %d: statusCode=%d, body=%s", i, output.StatusCode, output.Body)
	}
	return nil
}

// validateDNSFailureResponse checks that the recipient received a 400 response
// with a DNS resolution failure message from the enclave.
func validateDNSFailureResponse(logger zerolog.Logger, bodies [][]byte) error {
	if len(bodies) == 0 {
		return fmt.Errorf("expected at least 1 recipient request for DNS failure, got 0")
	}
	for i, body := range bodies {
		var output ResponseOutput
		if err := json.Unmarshal(body, &output); err != nil {
			return fmt.Errorf("response %d: failed to unmarshal: %w", i, err)
		}
		if output.StatusCode != 400 {
			return fmt.Errorf("response %d: expected statusCode 400, got %d (body: %s)", i, output.StatusCode, output.Body)
		}
		if !strings.Contains(output.Body, "upstream DNS resolution failed") {
			return fmt.Errorf("response %d: expected body to contain 'upstream DNS resolution failed', got: %s", i, output.Body)
		}
		logger.Info().Msgf("DNS failure response %d: statusCode=%d, body=%s", i, output.StatusCode, output.Body)
	}
	return nil
}

// validateTimeoutResponse checks that the recipient received a 504 response
// with an upstream timeout message from the enclave.
func validateTimeoutResponse(logger zerolog.Logger, bodies [][]byte) error {
	if len(bodies) == 0 {
		return fmt.Errorf("expected at least 1 recipient request for timeout, got 0")
	}
	for i, body := range bodies {
		var output ResponseOutput
		if err := json.Unmarshal(body, &output); err != nil {
			return fmt.Errorf("response %d: failed to unmarshal: %w", i, err)
		}
		if output.StatusCode != 504 {
			return fmt.Errorf("response %d: expected statusCode 504, got %d (body: %s)", i, output.StatusCode, output.Body)
		}
		if !strings.Contains(output.Body, "upstream request timed out") {
			return fmt.Errorf("response %d: expected body to contain 'upstream request timed out', got: %s", i, output.Body)
		}
		logger.Info().Msgf("Timeout response %d: statusCode=%d, body=%s", i, output.StatusCode, output.Body)
	}
	return nil
}

// validateRecipientRequests validates the ResponseOutput payloads that the
// workflow POSTed to the recipient server. Results arrive in arbitrary order,
// so validation checks that we received both test-message variants rather
// than relying on positional indexes.
func validateRecipientRequests(logger zerolog.Logger, bodies [][]byte) error {
	if len(bodies) < 2 {
		return fmt.Errorf("expected at least 2 recipient requests, got %d", len(bodies))
	}

	logger.Info().Msgf("Validating %d recipient responses...", len(bodies))

	var foundPlaintext, foundEncrypted int
	var plaintextCount, encryptedCount, errorCount int

	for i, body := range bodies {
		var output ResponseOutput
		if err := json.Unmarshal(body, &output); err != nil {
			logger.Error().Msgf("Response %d: failed to unmarshal ResponseOutput (len=%d, first100=%q): %v", i, len(body), truncate(body, 100), err)
			return fmt.Errorf("response %d: failed to unmarshal ResponseOutput: %w", i, err)
		}

		if output.StatusCode != 200 {
			logger.Error().Msgf("Response %d: unexpected statusCode=%d, body=%q", i, output.StatusCode, truncate([]byte(output.Body), 200))
			return fmt.Errorf("response %d: expected statusCode 200, got %d", i, output.StatusCode)
		}

		responseBody := []byte(output.Body)

		// Try to parse as JSON directly; if that fails, try decrypting.
		var jsonResponse map[string]any
		if err := json.Unmarshal(responseBody, &jsonResponse); err != nil {
			// Body is not JSON — it should be base64-encoded AES-GCM ciphertext.
			ciphertext, b64Err := base64.StdEncoding.DecodeString(string(responseBody))
			if b64Err != nil {
				logger.Error().Msgf("Response %d: body is not JSON and not valid base64 (bodyLen=%d, bodyHex=%s): %v",
					i, len(responseBody), hex.EncodeToString(truncateBytes(responseBody, 64)), b64Err)
				errorCount++
				continue
			}
			aesKey, decErr := hex.DecodeString(aesKeyForEncryptionTest)
			if decErr != nil {
				return fmt.Errorf("response %d: AES key decode failed: %w", i, decErr)
			}
			decrypted, decErr := util.AESGCMDecrypt(ciphertext, aesKey)
			if decErr != nil {
				logger.Error().Msgf("Response %d: base64-decoded but AES-GCM decrypt failed (ciphertextLen=%d): %v",
					i, len(ciphertext), decErr)
				errorCount++
				continue
			}
			logger.Info().Msgf("Response %d: decrypted (%d bytes -> %d bytes)", i, len(responseBody), len(decrypted))
			responseBody = decrypted
			if err2 := json.Unmarshal(responseBody, &jsonResponse); err2 != nil {
				logger.Error().Msgf("Response %d: decrypted body is not valid JSON: %v (decrypted=%q)", i, err2, truncate(decrypted, 200))
				errorCount++
				continue
			}
			encryptedCount++
		} else {
			plaintextCount++
		}

		// Only log first few and any errors to avoid flooding
		if i < 4 || i%10 == 0 {
			indent, _ := json.MarshalIndent(jsonResponse, "", "  ")
			logger.Info().Msgf("Response %d: %s", i, string(indent))
		}

		// Validate common fields
		urlStr, ok := jsonResponse["url"].(string)
		if !ok || !strings.Contains(urlStr, "postman-echo.com/post") {
			return fmt.Errorf("response %d: url mismatch, expected to contain 'postman-echo.com/post', got '%v'", i, jsonResponse["url"])
		}
		headers, ok := jsonResponse["headers"].(map[string]any)
		if !ok {
			return fmt.Errorf("response %d: headers are not in the expected format", i)
		}
		host, ok := headers["host"].(string)
		if !ok || !strings.Contains(host, "postman-echo.com") {
			return fmt.Errorf("response %d: host mismatch, got '%v'", i, headers["host"])
		}
		auth, ok := headers["authorization"].(string)
		if !ok || !strings.Contains(auth, "Bearer API123") {
			return fmt.Errorf("response %d: auth mismatch, got '%v'", i, headers["authorization"])
		}

		// Classify by data field
		switch jsonResponse["data"] {
		case "test message":
			foundPlaintext++
		case "test message 2":
			foundEncrypted++
		default:
			return fmt.Errorf("response %d: unexpected data value '%v'", i, jsonResponse["data"])
		}
	}

	logger.Info().Msgf("Validation summary: %d total, %d plaintext, %d encrypted, %d decryptErrors, foundPlaintext=%d, foundEncrypted=%d",
		len(bodies), plaintextCount, encryptedCount, errorCount, foundPlaintext, foundEncrypted)

	if foundPlaintext == 0 {
		return fmt.Errorf("plaintext response ('test message') not found in %d results", len(bodies))
	}
	if foundEncrypted == 0 {
		return fmt.Errorf("encrypted response ('test message 2') not found in %d results (decryptErrors=%d)", len(bodies), errorCount)
	}

	return nil
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
