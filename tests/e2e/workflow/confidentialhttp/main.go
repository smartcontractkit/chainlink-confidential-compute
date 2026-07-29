//go:build wasip1

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	confidentialhttp "github.com/smartcontractkit/cre-sdk-go/capabilities/networking/confidentialhttp"
	http "github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/smartcontractkit/chainlink-confidential-compute/tests/e2e/workflow/confidentialhttp/config"
)

func main() {
	wasm.NewRunner(func(configBytes []byte) (config.Config, error) {
		var cfg config.Config
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return config.Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
		}
		return cfg, nil
	}).Run(RunConfidentialHTTPWorkflow)
}

// RunConfidentialHTTPWorkflow sets up the workflow to accept HTTP triggers
func RunConfidentialHTTPWorkflow(cfg config.Config, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[config.Config], error) {
	return cre.Workflow[config.Config]{
		cre.Handler(
			http.Trigger(&http.Config{
				AuthorizedKeys: []*http.AuthorizedKey{
					{
						Type:      http.KeyType_KEY_TYPE_ECDSA_EVM,
						PublicKey: cfg.AuthorizedKey,
					},
				},
			}),
			onHTTPTrigger,
		),
	}, nil
}

// TriggerInput is the JSON payload sent in the HTTP trigger request.
// It contains the confidential HTTP request parameters.
type TriggerInput struct {
	// URL is the enclave endpoint
	URL string `json:"url"`
	// Method is the HTTP method (GET, POST, etc.)
	Method string `json:"method"`
	// Body is the request body (optional)
	Body string `json:"body,omitempty"`
	// Headers are request headers as key-value pairs
	Headers map[string]string `json:"headers,omitempty"`
	// TemplatePublicValues are public values for template substitution
	TemplatePublicValues map[string]string `json:"templatePublicValues,omitempty"`
	// VaultSecrets are secret identifiers to inject from the Vault DON
	VaultSecrets []SecretRef `json:"vaultSecrets,omitempty"`
	// CustomRootCACertPEM is an optional custom root CA certificate
	CustomRootCACertPEM string `json:"customRootCACertPem,omitempty"`
	// EncryptOutput indicates whether to encrypt the response
	EncryptOutput bool `json:"encryptOutput,omitempty"`
	// TimeoutMs is the request timeout in milliseconds (optional)
	TimeoutMs int64 `json:"timeoutMs,omitempty"`
}

// SecretRef identifies a secret in the Vault DON
type SecretRef struct {
	Key       string `json:"key"`
	Namespace string `json:"namespace,omitempty"`
	Owner     string `json:"owner,omitempty"`
}

// onHTTPTrigger handles incoming HTTP trigger requests.
// It calls confidential-http, then POSTs the result to cfg.URL (the recipient).
func onHTTPTrigger(cfg config.Config, runtime cre.Runtime, trigger *http.Payload) (string, error) {
	logger := runtime.Logger()
	logger.Info("Confidential HTTP workflow triggered")

	// Parse the trigger input
	var input TriggerInput
	if err := json.Unmarshal(trigger.Input, &input); err != nil {
		logger.Error("Failed to parse trigger input", "error", err)
		return "", fmt.Errorf("failed to parse trigger input: %w", err)
	}

	logger.Info("Processing confidential HTTP request",
		"url", input.URL,
		"method", input.Method,
		"hasBody", len(input.Body) > 0,
		"secretCount", len(input.VaultSecrets),
	)

	// Build the confidential HTTP request
	confReq := buildConfidentialHTTPRequest(input)

	// Call the confidential-http capability.
	// The capability handles consensus internally (it's an OCR-based capability).
	confClient := &confidentialhttp.Client{}
	result, err := confClient.SendRequest(runtime, confReq).Await()
	if err != nil {
		logger.Error("Confidential HTTP request failed", "error", err)
		return "", err
	}

	logger.Info("Confidential HTTP request completed",
		"statusCode", result.StatusCode,
		"bodyLength", len(result.Body),
	)

	// Serialize the response to send to the recipient endpoint.
	// When encryption is enabled, result.Body contains raw AES-GCM
	// ciphertext (binary). We must base64-encode it so that
	// json.Marshal doesn't corrupt non-UTF-8 bytes.
	body := string(result.Body)
	if input.EncryptOutput {
		body = base64.StdEncoding.EncodeToString(result.Body)
	}
	output := ResponseOutput{
		StatusCode: result.StatusCode,
		Body:       body,
		Headers:    flattenHeaders(result.MultiHeaders),
	}
	outputBytes, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("failed to marshal response output: %w", err)
	}

	// Send the result to the recipient endpoint via the http-action capability.
	// RunInNodeMode runs the function on each node independently, then
	// ConsensusIdenticalAggregation ensures all nodes agree on the result.
	promise := cre.RunInNodeMode(cfg, runtime,
		func(cfg config.Config, nodeRuntime cre.NodeRuntime) (string, error) {
			httpClient := &http.Client{}
			req := &http.Request{
				Url:    cfg.URL,
				Method: "POST",
				Body:   outputBytes,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			}
			_, err := httpClient.SendRequest(nodeRuntime, req).Await()
			if err != nil {
				return "", fmt.Errorf("failed to send result to recipient: %w", err)
			}
			return "sent", nil
		},
		cre.ConsensusIdenticalAggregation[string](),
	)

	sent, err := promise.Await()
	if err != nil {
		return "", fmt.Errorf("consensus failed for recipient delivery: %w", err)
	}

	logger.Info("Result delivered to recipient", "status", sent)
	return sent, nil
}

// ResponseOutput is the JSON response returned by the workflow
type ResponseOutput struct {
	StatusCode uint32            `json:"statusCode"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// buildConfidentialHTTPRequest converts TriggerInput to ConfidentialHTTPRequest
func buildConfidentialHTTPRequest(input TriggerInput) *confidentialhttp.ConfidentialHTTPRequest {
	// Build headers
	multiHeaders := make(map[string]*confidentialhttp.HeaderValues)
	for k, v := range input.Headers {
		multiHeaders[k] = &confidentialhttp.HeaderValues{Values: []string{v}}
	}

	// Build vault secrets
	var vaultSecrets []*confidentialhttp.SecretIdentifier
	for _, s := range input.VaultSecrets {
		secret := &confidentialhttp.SecretIdentifier{
			Key:       s.Key,
			Namespace: s.Namespace,
		}
		if s.Owner != "" {
			secret.Owner = &s.Owner
		}
		vaultSecrets = append(vaultSecrets, secret)
	}

	httpReq := &confidentialhttp.HTTPRequest{
		Url:                  input.URL,
		Method:               input.Method,
		MultiHeaders:         multiHeaders,
		TemplatePublicValues: input.TemplatePublicValues,
		CustomRootCaCertPem:  []byte(input.CustomRootCACertPEM),
		EncryptOutput:        input.EncryptOutput,
	}
	if input.TimeoutMs > 0 {
		httpReq.Timeout = durationpb.New(time.Duration(input.TimeoutMs) * time.Millisecond)
	}

	if input.Body != "" {
		httpReq.Body = &confidentialhttp.HTTPRequest_BodyString{BodyString: input.Body}
	}

	return &confidentialhttp.ConfidentialHTTPRequest{
		Request:         httpReq,
		VaultDonSecrets: vaultSecrets,
	}
}

// flattenHeaders converts MultiHeaders to a simple map (taking first value of each)
func flattenHeaders(multiHeaders map[string]*confidentialhttp.HeaderValues) map[string]string {
	result := make(map[string]string)
	for k, v := range multiHeaders {
		if v != nil && len(v.Values) > 0 {
			result[k] = v.Values[0]
		}
	}
	return result
}
