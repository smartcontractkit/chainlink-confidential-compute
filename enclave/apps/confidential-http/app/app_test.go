package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enclavetypes "github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-http/types"
	httpsmocks "github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outbound-https/mocks"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// testEmitter captures emitted metrics for testing
type testEmitter struct {
	mu      sync.Mutex
	metrics []struct {
		event   string
		details map[string]any
	}
}

func (e *testEmitter) Emit(event string, details map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metrics = append(e.metrics, struct {
		event   string
		details map[string]any
	}{event: event, details: details})
}

func (e *testEmitter) getMetrics() []struct {
	event   string
	details map[string]any
} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.metrics
}

// generateSelfSignedCert generates a self-signed certificate and its private key.
// It returns the PEM encoded certificate and key.
// This function can be used to create both the "untrusted" server cert
// and a "trusted" root CA for the client, ensuring they are distinct.
func generateSelfSignedCert(commonName string, dnsNames []string, ipAddresses []net.IP) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Mark as CA so it can sign itself or others
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

// generateSignedCert generates a certificate signed by a given CA.
func generateSignedCert(parentCert *x509.Certificate, parentKey *rsa.PrivateKey, commonName string, dnsNames []string, ipAddresses []net.IP) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

// Helper to decode PEM blocks (used for x509.ParseCertificate and ParsePKCS1PrivateKey)
func decodePEM(pemBytes []byte) []byte {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic("failed to parse PEM block")
	}
	return block.Bytes
}

func TestHTTPEnclaveApp_Execute(t *testing.T) {
	// Create a mock HTTP client that echoes back the request body in the response.
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		var requestBody []byte
		var err error
		bodyString := ""
		if req.Body != nil {
			requestBody, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			bodyString = string(requestBody)
		}

		responseBody := map[string]interface{}{
			"method":  req.Method,
			"url":     req.URL.String(),
			"body":    bodyString,
			"headers": req.Header,
		}
		respBytes, err := json.Marshal(responseBody)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(respBytes)),
			Header: http.Header{
				"Content-Type":   []string{"application/json"},
				"X-Request-Id":   []string{"test-req-id"},
				"X-Multi-Header": []string{"val1", "val2"},
			},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	secretsMap := map[string][]byte{
		"token":    []byte("abc123Token"),
		"secret":   []byte("sensitiveData123"),
		"apiKey":   []byte("API-KEY-456"),
		"username": []byte("johnDoe"),
		"password": []byte("securePassword"),
	}

	tests := []struct {
		name                    string
		request                 *enclavetypes.Request
		secretsMap              map[string][]byte
		expectedError           bool
		expectedErrorCode       int
		expectedURL             string
		expectedRequestBody     string
		expectedHeaders         map[string]string
		expectedResponseHeaders map[string][]string
	}{
		{
			name: "standard post request",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"key":"{{.secret}}", "action":"{{.action}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
					"X-Username":    {Values: []string{"{{.username}}"}},
					"Content-Type":  {Values: []string{"application/json"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "test-action",
				},
			},
			secretsMap:          secretsMap,
			expectedURL:         "https://example.com/api",
			expectedRequestBody: `{"key":"sensitiveData123", "action":"test-action"}`,
			expectedHeaders: map[string]string{
				"Authorization": "Bearer abc123Token",
				"X-Username":    "johnDoe",
				"Content-Type":  "application/json",
			},
			expectedResponseHeaders: map[string][]string{
				"Content-Type":   {"application/json"},
				"X-Request-Id":   {"test-req-id"},
				"X-Multi-Header": {"val1", "val2"},
			},
		},
		{
			name: "get request",
			request: &enclavetypes.Request{
				Method: http.MethodGet,
				Url:    "https://example.com/api?param=get-data",
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
				},
			},
			secretsMap:  secretsMap,
			expectedURL: "https://example.com/api?param=get-data",
			expectedHeaders: map[string]string{
				"Authorization": "Bearer abc123Token",
			},
		},
		{
			name: "put request",
			request: &enclavetypes.Request{
				Method: http.MethodPut,
				Url:    "https://example.com/api/resource/123",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"updated":"{{.secret}}", "other":"{{.other}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
					"Content-Type":  {Values: []string{"application/json"}},
				},
				TemplatePublicValues: map[string]string{
					"other": "public-data",
				},
			},
			secretsMap:          secretsMap,
			expectedURL:         "https://example.com/api/resource/123",
			expectedRequestBody: `{"updated":"sensitiveData123", "other":"public-data"}`,
			expectedHeaders: map[string]string{
				"Authorization": "Bearer abc123Token",
				"Content-Type":  "application/json",
			},
		},
		{
			name: "delete request",
			request: &enclavetypes.Request{
				Method: http.MethodDelete,
				Url:    "https://example.com/api/resource/456",
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
				},
				TemplatePublicValues: map[string]string{},
			},
			secretsMap:  secretsMap,
			expectedURL: "https://example.com/api/resource/456",
			expectedHeaders: map[string]string{
				"Authorization": "Bearer abc123Token",
			},
		},
		{
			name: "header with comma-separated values",
			request: &enclavetypes.Request{
				Method: http.MethodGet,
				Url:    "https://example.com/api/headers-comma",
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Accept":        {Values: []string{"application/json, text/plain, */*"}},
					"X-Custom-List": {Values: []string{"{{.token}}, value2, {{.apiKey}}"}},
				},
				TemplatePublicValues: map[string]string{},
			},
			secretsMap:  secretsMap,
			expectedURL: "https://example.com/api/headers-comma",
			expectedHeaders: map[string]string{
				"Accept":        "application/json, text/plain, */*",
				"X-Custom-List": "abc123Token, value2, API-KEY-456",
			},
		},
		{
			name: "xml content-type",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api/xml",
				Body:   &enclavetypes.Request_BodyString{BodyString: `<request><user>{{.username}}</user><data>{{.secret}}</data><action>{{.action}}</action></request>`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Basic {{.apiKey}}"}},
					"Content-Type":  {Values: []string{"application/xml"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "xml-action",
				},
			},
			secretsMap:          secretsMap,
			expectedURL:         "https://example.com/api/xml",
			expectedRequestBody: `<request><user>johnDoe</user><data>sensitiveData123</data><action>xml-action</action></request>`,
			expectedHeaders: map[string]string{
				"Authorization": "Basic API-KEY-456",
				"Content-Type":  "application/xml",
			},
		},
		{
			name: "form url encoded",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api/form",
				Body:   &enclavetypes.Request_BodyString{BodyString: `username={{.username}}&password={{.password}}&action={{.action}}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"X-CSRF-Token": {Values: []string{"{{.token}}"}},
					"Content-Type": {Values: []string{"application/x-www-form-urlencoded"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "login",
				},
			},
			secretsMap:          secretsMap,
			expectedURL:         "https://example.com/api/form",
			expectedRequestBody: `username=johnDoe&password=securePassword&action=login`,
			expectedHeaders: map[string]string{
				"X-Csrf-Token": "abc123Token",
				"Content-Type": "application/x-www-form-urlencoded",
			},
		},
		{
			name: "missing method",
			request: &enclavetypes.Request{
				Url:  "https://example.com/api",
				Body: &enclavetypes.Request_BodyString{BodyString: `{"key":"{{.secret}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Content-Type": {Values: []string{"application/json"}},
				},
			},
			secretsMap:        secretsMap,
			expectedError:     true,
			expectedErrorCode: http.StatusBadRequest,
		},
		{
			name: "overlapping secret and public inputs",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"key":"{{.secret}}"}`},
				TemplatePublicValues: map[string]string{
					"secret": "public-secret-value",
				},
			},
			secretsMap:        secretsMap,
			expectedError:     true,
			expectedErrorCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputDataBytes, err := proto.Marshal(tt.request)
			require.NoError(t, err)

			// Use testEmitter to capture metrics
			testEmit := &testEmitter{}

			var requestID [32]byte
			copy(requestID[:], "request_id")
			output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, tt.secretsMap, testEmit)

			if tt.expectedError {
				require.NotNil(t, execError)
				assert.Equal(t, tt.expectedErrorCode, execError.Code)
				return
			}

			require.Nil(t, execError)
			require.NotNil(t, output)

			var response enclavetypes.Response
			err = proto.Unmarshal(output, &response)
			require.NoError(t, err)

			assert.Equal(t, uint32(http.StatusOK), response.StatusCode)

			var outputs map[string]interface{}
			err = json.Unmarshal(response.Body, &outputs)
			require.NoError(t, err)

			assert.Contains(t, outputs, "url", "Response outputs should contain 'url' key")
			assert.Equal(t, tt.expectedURL, outputs["url"].(string))
			assert.Equal(t, tt.request.Method, outputs["method"])

			if tt.expectedRequestBody != "" {
				body, ok := outputs["body"].(string)
				require.True(t, ok, "Body should be a string")
				assert.Equal(t, tt.expectedRequestBody, body)
			} else if util.MethodUsesBody(tt.request.Method) &&
				(tt.request.GetBodyString() != "" || len(tt.request.GetBodyBytes()) > 0) {
				t.Fatalf("test %s is missing expected request body validation with method %s (bodyString=%q, bodyBytes=%q)",
					tt.name, tt.request.Method, tt.request.GetBodyString(), string(tt.request.GetBodyBytes()))
			}

			// Validate response headers if expected.
			if tt.expectedResponseHeaders != nil {
				require.NotNil(t, response.MultiHeaders, "response.MultiHeaders should not be nil")
				for key, expectedVals := range tt.expectedResponseHeaders {
					hv, ok := response.MultiHeaders[key]
					require.True(t, ok, "response header %s should exist", key)
					assert.ElementsMatch(t, expectedVals, hv.Values,
						"response header %s values should match", key)
				}
			}

			// Validate headers if provided.
			if headers, ok := outputs["headers"].(map[string]interface{}); ok && len(tt.expectedHeaders) > 0 {
				for headerName, expectedValue := range tt.expectedHeaders {
					canonicalHeaderName := textproto.CanonicalMIMEHeaderKey(headerName)

					headerValue, exists := headers[canonicalHeaderName]
					assert.True(t, exists, "Header %s should exist", headerName)

					if headerArray, ok := headerValue.([]interface{}); ok && len(headerArray) > 0 {
						var found bool
						for _, v := range headerArray {
							if vStr, ok := v.(string); ok && vStr == expectedValue {
								found = true
								break
							}
						}
						assert.True(t, found, "Header %s should contain %s", headerName, expectedValue)
					} else if headerString, ok := headerValue.(string); ok {
						assert.Equal(t, expectedValue, headerString,
							"Header %s should equal %s", headerName, expectedValue)
					}
				}
			}

			// Verify metrics were emitted
			metrics := testEmit.getMetrics()
			require.Len(t, metrics, 2, "should emit http_batch_started and http_batch_completed")
			assert.Equal(t, "http_batch_started", metrics[0].event)
			assert.Equal(t, 1, metrics[0].details["num_requests"])
			assert.Equal(t, "http_batch_completed", metrics[1].event)
			assert.Equal(t, 1, metrics[1].details["num_requests"])
			duration, ok := metrics[1].details["duration_seconds"].(float64)
			require.True(t, ok, "duration_seconds should be a float64")
			assert.GreaterOrEqual(t, duration, float64(0), "duration should be non-negative")
		})
	}
}

func TestHTTPEnclave_InvalidAppID(t *testing.T) {
	app := NewHTTPEnclaveApp(nil)

	inputDataBytes, err := proto.Marshal(&enclavetypes.Request{})
	require.NoError(t, err)

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, "invalid-app-id", inputDataBytes, nil, emitter.NewNoOpEmitter())
	require.NotNil(t, execError)
	require.Nil(t, output)
	assert.Equal(t, http.StatusBadRequest, execError.Code)
	assert.Contains(t, execError.Error, "invalid app ID")
}

func TestHTTPEnclaveApp_Execute_WithHTTPErrors(t *testing.T) {
	// Test requests that return HTTP errors.
	errorMockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		url := req.URL.String()

		var statusCode int
		var responseBody map[string]interface{}

		switch {
		case strings.Contains(url, "/success"):
			statusCode = http.StatusOK
			responseBody = map[string]interface{}{
				"status": "success",
				"url":    url,
				"method": req.Method,
			}
		case strings.Contains(url, "/client-error"):
			statusCode = http.StatusBadRequest
			responseBody = map[string]interface{}{
				"error":  "bad request",
				"url":    url,
				"method": req.Method,
			}
		case strings.Contains(url, "/server-error"):
			statusCode = http.StatusInternalServerError
			responseBody = map[string]interface{}{
				"error":  "internal server error",
				"url":    url,
				"method": req.Method,
			}
		case strings.Contains(url, "/not-found"):
			statusCode = http.StatusNotFound
			responseBody = map[string]interface{}{
				"error":  "not found",
				"url":    url,
				"method": req.Method,
			}
		default:
			statusCode = http.StatusOK
			responseBody = map[string]interface{}{
				"status": "default success",
				"url":    url,
				"method": req.Method,
			}
		}

		respBytes, err := json.Marshal(responseBody)
		if err != nil {
			return nil, err
		}

		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(bytes.NewBuffer(respBytes)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(errorMockClient)

	secretsMap := map[string][]byte{
		"token":  []byte("abc123Token"),
		"apiKey": []byte("API-KEY-456"),
	}

	tests := []struct {
		name               string
		request            *enclavetypes.Request
		expectedStatusCode uint32
		expectedError      string
	}{
		{
			name: "success response",
			request: &enclavetypes.Request{
				Url:    "https://example.com/success",
				Method: http.MethodGet,
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
				},
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "client error response",
			request: &enclavetypes.Request{
				Url:    "https://example.com/client-error",
				Method: http.MethodPost,
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"data":"test"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Content-Type": {Values: []string{"application/json"}},
				},
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "bad request",
		},
		{
			name: "server error response",
			request: &enclavetypes.Request{
				Url:    "https://example.com/server-error",
				Method: http.MethodPut,
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Content-Type": {Values: []string{"application/json"}},
				},
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "internal server error",
		},
		{
			name: "not found response",
			request: &enclavetypes.Request{
				Url:    "https://example.com/not-found",
				Method: http.MethodDelete,
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"X-API-Key": {Values: []string{"{{.apiKey}}"}},
				},
			},
			expectedStatusCode: http.StatusNotFound,
			expectedError:      "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputDataBytes, err := proto.Marshal(tt.request)
			require.NoError(t, err)

			var requestID [32]byte
			copy(requestID[:], "request_id")
			output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())
			require.Nil(t, execError)
			require.NotNil(t, output)

			var response enclavetypes.Response
			err = proto.Unmarshal(output, &response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatusCode, response.StatusCode)

			var httpResp map[string]interface{}
			err = json.Unmarshal(response.Body, &httpResp)
			require.NoError(t, err)

			assert.Contains(t, httpResp, "url")
			assert.Contains(t, httpResp, "method")

			if tt.expectedError != "" {
				assert.Contains(t, httpResp, "error")
				assert.Equal(t, tt.expectedError, httpResp["error"])
			}
		})
	}
}

func TestHTTPEnclaveApp_ExecuteHTTPRequest_TemplateProcessing(t *testing.T) {
	// Test template processing edge cases directly
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient).(*httpEnclaveApp)

	tests := []struct {
		name         string
		request      *enclavetypes.Request
		templateData map[string]interface{}
		expectError  bool
	}{
		{
			name: "valid template processing",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"key":"{{.secret}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.token}}"}},
				},
			},
			templateData: map[string]interface{}{
				"secret": "test-secret",
				"token":  "test-token",
			},
		},
		{
			name: "invalid body template",
			request: &enclavetypes.Request{
				Method: http.MethodPost,
				Url:    "https://example.com/api",
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"key":"{{.validKey.InvalidMethod}}"}`}, // Calling method on wrong type
			},
			templateData: map[string]interface{}{"validKey": "string"},
			expectError:  true,
		},
		{
			name: "invalid header template",
			request: &enclavetypes.Request{
				Method: http.MethodGet,
				Url:    "https://example.com/api",
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{unclosed_template"}},
				},
			},
			templateData: map[string]interface{}{},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := app.executeHTTPRequest(tt.request, tt.templateData)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
			}
		})
	}
}

func TestHTTPEnclaveApp_Execute_BytesBody(t *testing.T) {
	// Test that bytes body is passed through without templating
	var capturedBody []byte
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		var err error
		if req.Body != nil {
			capturedBody, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	// Create binary data that would be invalid as a template
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, '{', '{', '.', 's', 'e', 'c', 'r', 'e', 't', '}', '}'}

	request := &enclavetypes.Request{
		Method: http.MethodPost,
		Url:    "https://example.com/api/binary",
		Body:   &enclavetypes.Request_BodyBytes{BodyBytes: binaryData},
		MultiHeaders: map[string]*enclavetypes.HeaderValues{
			"Content-Type": {Values: []string{"application/octet-stream"}},
		},
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	secretsMap := map[string][]byte{
		"secret": []byte("should-not-be-substituted"),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())

	require.Nil(t, execError)
	require.NotNil(t, output)

	// Verify the body was sent as raw bytes without template substitution
	assert.Equal(t, binaryData, capturedBody, "Binary body should be passed through unchanged without templating")

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
}

func TestHTTPEnclaveApp_Execute_StringBodyWithTemplating(t *testing.T) {
	// Test that string body has templating applied
	var capturedBody string
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			capturedBody = string(bodyBytes)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	request := &enclavetypes.Request{
		Method: http.MethodPost,
		Url:    "https://example.com/api/json",
		Body:   &enclavetypes.Request_BodyString{BodyString: `{"secret":"{{.secret}}"}`},
		MultiHeaders: map[string]*enclavetypes.HeaderValues{
			"Content-Type": {Values: []string{"application/json"}},
		},
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	secretsMap := map[string][]byte{
		"secret": []byte("my-secret-value"),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())

	require.Nil(t, execError)
	require.NotNil(t, output)

	// Verify the body had templating applied
	assert.Equal(t, `{"secret":"my-secret-value"}`, capturedBody, "String body should have template substitution applied")

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
}

func TestHTTPEnclaveApp_Execute_DoesNotReuseConnectionsAcrossExecutions(t *testing.T) {
	var connectionCount atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectionCount.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	enclaveApp := NewHTTPEnclaveApp(&http.Client{Transport: transport})
	requestBytes, err := proto.Marshal(&enclavetypes.Request{
		Method: http.MethodGet,
		Url:    server.URL,
	})
	require.NoError(t, err)

	for i := range 2 {
		var requestID [32]byte
		requestID[0] = byte(i + 1)
		_, execErr := enclaveApp.Execute(
			requestID,
			types.AppIDConfidentialHTTP,
			requestBytes,
			nil,
			&testEmitter{},
		)
		require.Nil(t, execErr)
	}

	assert.Equal(t, int32(2), connectionCount.Load())
}

func TestHandleExecute_WithRealHTTPSOutbound_TrustedCA(t *testing.T) {
	// Generate a CA and a server cert signed by that CA
	caCertPEM, caKeyPEM, err := generateSelfSignedCert("Test Root CA", nil, nil)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(decodePEM(caCertPEM))
	require.NoError(t, err)
	caKey, err := x509.ParsePKCS1PrivateKey(decodePEM(caKeyPEM))
	require.NoError(t, err)

	serverCertPEM, serverKeyPEM, err := generateSignedCert(
		caCert, caKey, "trusted.server.com",
		[]string{"trusted.server.com", "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	require.NoError(t, err)
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// Start a real HTTPS server
	realServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte("Hello from secure test server!"))
		require.NoError(t, err)
	}))
	realServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	realServer.StartTLS()
	defer realServer.Close()

	// Set up an enclaveServer instance with a real HTTP client
	app := httpEnclaveApp{
		httpClient: util.NewUnrestrictedClient(),
		newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.TLSClientConfig = tlsCfg
			return &http.Client{Transport: tr}
		},
	}

	// Prepare a Request that points to the real HTTPS server, with the correct CA
	request := enclavetypes.Request{
		Method:              http.MethodGet,
		Url:                 realServer.URL,
		CustomRootCaCertPem: caCertPEM,
		MultiHeaders:        map[string]*enclavetypes.HeaderValues{},
	}

	// Call executeHTTPRequest directly
	resp, err := app.executeHTTPRequest(&request, map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusOK), resp.StatusCode)
	assert.Contains(t, string(resp.Body), "Hello from secure test server!")
}

func TestExecuteHTTPRequest_WithRealHTTPSOutbound_UntrustedCA(t *testing.T) {
	// Generate an untrusted server cert (self-signed)
	serverCertPEM, serverKeyPEM, err := generateSelfSignedCert("untrusted.server.com", []string{"untrusted.server.com", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// Generate a different CA (not used to sign the server cert)
	unusedCACertPEM, _, err := generateSelfSignedCert("Unused Root CA", nil, nil)
	require.NoError(t, err)

	// Start a real HTTPS server with the untrusted cert
	realServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte("Hello from untrusted test server!"))
		require.NoError(t, err)
	}))
	realServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	realServer.StartTLS()
	defer realServer.Close()

	// Set up an enclaveServer instance with a real HTTP client
	app := httpEnclaveApp{
		httpClient: http.DefaultClient,
		newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.TLSClientConfig = tlsCfg
			return &http.Client{Transport: tr}
		},
	}

	// Prepare a Request that points to the real HTTPS server, with the WRONG CA
	request := enclavetypes.Request{
		Method:              http.MethodGet,
		Url:                 realServer.URL,
		CustomRootCaCertPem: unusedCACertPEM, // This CA did NOT sign the server's cert
		MultiHeaders:        map[string]*enclavetypes.HeaderValues{},
	}

	// Call executeHTTPRequest directly and expect an error
	resp, err := app.executeHTTPRequest(&request, map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error making http request")
	assert.Equal(t, uint32(0), resp.StatusCode)
}

func TestHTTPEnclaveApp_Execute_Timeout(t *testing.T) {
	// Create a mock HTTP client that delays longer than the timeout and respects context cancellation
	slowClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		// Use a select to respect context cancellation
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(5 * time.Second):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		}
	})

	app := NewHTTPEnclaveApp(slowClient)

	// Create request with a short timeout
	request := &enclavetypes.Request{
		Method:  http.MethodGet,
		Url:     "https://example.com/slow-endpoint",
		Timeout: durationpb.New(50 * time.Millisecond),
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	testEmit := &testEmitter{}
	var requestID [32]byte
	copy(requestID[:], "request_id")

	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

	// Should return a 504 Gateway Timeout response, not an error
	require.Nil(t, execError)
	require.NotNil(t, output)

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusGatewayTimeout), response.StatusCode)
	assert.Equal(t, "upstream request timed out", string(response.Body))
}

func TestHTTPEnclaveApp_Execute_Timeout_RealServer(t *testing.T) {
	// Real server that ignores cancellation and sleeps
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		_, _ = w.Write([]byte("too late"))
	}))
	defer slowServer.Close()

	app := NewHTTPEnclaveApp(http.DefaultClient)

	request := &enclavetypes.Request{
		Method:  http.MethodGet,
		Url:     slowServer.URL,
		Timeout: durationpb.New(50 * time.Millisecond),
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	var requestID [32]byte
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, &testEmitter{})

	// Should return a 504 Gateway Timeout response, not an error
	require.Nil(t, execError)
	require.NotNil(t, output)

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusGatewayTimeout), response.StatusCode)
	assert.Equal(t, "upstream request timed out", string(response.Body))
}

func TestHTTPEnclaveApp_Execute_SSRFBlockedReturns400(t *testing.T) {
	// TLS server on loopback (127.0.0.1) — a private address the restricted
	// client must refuse via its SSRF policy.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should not be reached"))
	}))
	defer server.Close()

	// nil httpClient -> restricted safeurl client with SSRF protection.
	app := NewHTTPEnclaveApp(nil)

	request := enclavetypes.Request{
		Method: http.MethodGet,
		Url:    server.URL,
	}

	inputDataBytes, err := proto.Marshal(&request)
	require.NoError(t, err)

	var requestID [32]byte
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, &testEmitter{})

	// Should return a 400 Bad Request response, not an error.
	require.Nil(t, execError)
	require.NotNil(t, output)

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusBadRequest), response.StatusCode)
	assert.Equal(t, "upstream request blocked by enclave network policy", string(response.Body))
}

func TestHTTPEnclaveApp_Execute_TimeoutNotReached(t *testing.T) {
	// Create a mock HTTP client that responds quickly
	fastClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(fastClient)

	// Create request with a generous timeout
	request := &enclavetypes.Request{
		Method:  http.MethodGet,
		Url:     "https://example.com/fast-endpoint",
		Timeout: durationpb.New(5 * time.Second),
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	testEmit := &testEmitter{}
	var requestID [32]byte
	copy(requestID[:], "request_id")

	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

	// Should succeed without timeout
	require.Nil(t, execError)
	require.NotNil(t, output)

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)
	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
}

func TestHTTPEnclaveApp_Execute_DefaultTimeoutApplied(t *testing.T) {
	// Verify that when no timeout is specified in the request, the default timeout is applied to the context
	var capturedCtx context.Context
	client := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		capturedCtx = req.Context()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(client)

	// Request with no Timeout field set (nil)
	request := &enclavetypes.Request{
		Method: http.MethodGet,
		Url:    "https://example.com/api",
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	var requestID [32]byte
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, &testEmitter{})
	require.Nil(t, execError)
	require.NotNil(t, output)

	// The context should have had a deadline set (from the default timeout)
	require.NotNil(t, capturedCtx)
	deadline, ok := capturedCtx.Deadline()
	assert.True(t, ok, "context should have a deadline when no timeout is specified")
	// The deadline should be approximately DefaultEnclaveRequestTimeout from now (within a reasonable margin)
	assert.WithinDuration(t, time.Now().Add(types.DefaultEnclaveRequestTimeout), deadline, 5*time.Second)
}

func TestHTTPEnclaveApp_Execute_CustomTimeoutApplied(t *testing.T) {
	// Verify that a custom timeout specified in the request is applied to the context
	var capturedCtx context.Context
	client := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		capturedCtx = req.Context()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(client)

	customTimeout := 10 * time.Second
	request := &enclavetypes.Request{
		Method:  http.MethodGet,
		Url:     "https://example.com/api",
		Timeout: durationpb.New(customTimeout),
	}

	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	var requestID [32]byte
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, &testEmitter{})
	require.Nil(t, execError)
	require.NotNil(t, output)

	// The context should have a deadline matching the custom timeout
	require.NotNil(t, capturedCtx)
	deadline, ok := capturedCtx.Deadline()
	assert.True(t, ok, "context should have a deadline when custom timeout is specified")
	assert.WithinDuration(t, time.Now().Add(customTimeout), deadline, 2*time.Second)
}

func TestConvertHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    http.Header
		expected map[string]*enclavetypes.HeaderValues
	}{
		{
			name:     "nil header",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty header",
			input:    http.Header{},
			expected: nil,
		},
		{
			name: "single value per key",
			input: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Request-Id": []string{"abc123"},
			},
			expected: map[string]*enclavetypes.HeaderValues{
				"Content-Type": {Values: []string{"application/json"}},
				"X-Request-Id": {Values: []string{"abc123"}},
			},
		},
		{
			name: "multiple values preserved per key",
			input: http.Header{
				"Set-Cookie":   []string{"a=1", "b=2"},
				"X-Multi":      []string{"val1", "val2", "val3"},
				"Content-Type": []string{"application/json"},
			},
			expected: map[string]*enclavetypes.HeaderValues{
				"Set-Cookie":   {Values: []string{"a=1", "b=2"}},
				"X-Multi":      {Values: []string{"val1", "val2", "val3"}},
				"Content-Type": {Values: []string{"application/json"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertHeaders(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPEnclaveApp_Execute_CustomRootCACert(t *testing.T) {
	// Generate a self-signed root CA certificate
	rootCACertPEM, rootCAKeyPEM, err := generateSelfSignedCert("Test Root CA", nil, nil)
	require.NoError(t, err)

	// Parse the root CA cert and key for signing the server cert
	rootCACert, err := x509.ParseCertificate(decodePEM(rootCACertPEM))
	require.NoError(t, err)
	rootCAKey, err := x509.ParsePKCS1PrivateKey(decodePEM(rootCAKeyPEM))
	require.NoError(t, err)

	// Generate a server certificate signed by our root CA
	serverCertPEM, serverKeyPEM, err := generateSignedCert(rootCACert, rootCAKey, "localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	// Create TLS config for the test server
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// Create a test HTTPS server with our custom certificate
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success from custom CA server"}`))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	t.Run("succeeds with correct custom root CA", func(t *testing.T) {
		// Use unrestricted clients so we can reach the local test server
		app := &httpEnclaveApp{
			httpClient: util.NewUnrestrictedClient(),
			newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
				tr := http.DefaultTransport.(*http.Transport).Clone()
				tr.TLSClientConfig = tlsCfg
				return &http.Client{Transport: tr}
			},
		}

		request := enclavetypes.Request{
			Method:              http.MethodGet,
			Url:                 server.URL + "/test",
			CustomRootCaCertPem: rootCACertPEM,
		}

		inputDataBytes, err := proto.Marshal(&request)
		require.NoError(t, err)

		testEmit := &testEmitter{}
		var requestID [32]byte
		copy(requestID[:], "request_id")

		output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

		require.Nil(t, execError, "expected no error when using correct custom root CA")
		require.NotNil(t, output)

		var response enclavetypes.Response
		err = proto.Unmarshal(output, &response)
		require.NoError(t, err)
		assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
		assert.Contains(t, string(response.Body), "success from custom CA server")
	})

	t.Run("fails without custom root CA", func(t *testing.T) {
		// Loopback-reaching client that still validates TLS against system
		// roots, so the failure comes from the untrusted self-signed cert
		// rather than the SSRF policy blocking 127.0.0.1.
		app := &httpEnclaveApp{
			httpClient: util.NewUnrestrictedClient(),
			newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
				tr := http.DefaultTransport.(*http.Transport).Clone()
				tr.TLSClientConfig = tlsCfg
				return &http.Client{Transport: tr}
			},
		}

		request := enclavetypes.Request{
			Method: http.MethodGet,
			Url:    server.URL + "/test",
			// No CustomRootCaCertPem - should fail
		}

		inputDataBytes, err := proto.Marshal(&request)
		require.NoError(t, err)

		testEmit := &testEmitter{}
		var requestID [32]byte
		copy(requestID[:], "request_id")

		_, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

		require.NotNil(t, execError, "expected error when custom root CA is not provided")
		assert.Contains(t, execError.Error, "error making http request")
	})

	t.Run("fails with wrong custom root CA", func(t *testing.T) {
		// Generate a different root CA that didn't sign the server cert
		wrongCACertPEM, _, err := generateSelfSignedCert("Wrong Root CA", nil, nil)
		require.NoError(t, err)

		// Loopback-reaching client so the failure comes from the wrong CA at
		// TLS verification, not the SSRF policy blocking 127.0.0.1.
		app := &httpEnclaveApp{
			httpClient: util.NewUnrestrictedClient(),
			newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
				tr := http.DefaultTransport.(*http.Transport).Clone()
				tr.TLSClientConfig = tlsCfg
				return &http.Client{Transport: tr}
			},
		}

		request := enclavetypes.Request{
			Method:              http.MethodGet,
			Url:                 server.URL + "/test",
			CustomRootCaCertPem: wrongCACertPEM,
		}

		inputDataBytes, err := proto.Marshal(&request)
		require.NoError(t, err)

		testEmit := &testEmitter{}
		var requestID [32]byte
		copy(requestID[:], "request_id")

		_, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

		require.NotNil(t, execError, "expected error when using wrong custom root CA")
		assert.Contains(t, execError.Error, "error making http request")
	})

	t.Run("fails with invalid PEM", func(t *testing.T) {
		app := NewHTTPEnclaveApp(nil)

		request := enclavetypes.Request{
			Method:              http.MethodGet,
			Url:                 server.URL + "/test",
			CustomRootCaCertPem: []byte("not a valid PEM"),
		}

		inputDataBytes, err := proto.Marshal(&request)
		require.NoError(t, err)

		testEmit := &testEmitter{}
		var requestID [32]byte
		copy(requestID[:], "request_id")

		_, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, nil, testEmit)

		require.NotNil(t, execError, "expected error when custom root CA PEM is invalid")
		assert.Contains(t, execError.Error, "error parsing custom root CA certificate")
	})
}

func TestHTTPEnclaveApp_Execute_AESGCMBodyEncryption(t *testing.T) {
	expectedBody := `{"secret":"data"}`
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(expectedBody)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	request := &enclavetypes.Request{
		Method:        http.MethodGet,
		Url:           "https://example.com/api",
		EncryptOutput: true,
	}
	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	// Generate a valid AES-256 key and hex-encode it (as the vault stores it).
	aesKey := make([]byte, 32)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)
	aesKeyHex := []byte(hex.EncodeToString(aesKey))

	secretsMap := map[string][]byte{
		types.AESGCMEncryptionKey: aesKeyHex,
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())
	require.Nil(t, execError)
	require.NotNil(t, output)

	// Unmarshal the proto — should succeed because only Body is encrypted.
	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)

	// Status code and headers should be plaintext.
	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
	require.NotEmpty(t, response.MultiHeaders)

	// Body should be encrypted (not equal to original).
	assert.NotEqual(t, expectedBody, string(response.Body))

	// Decrypt body and verify it matches original (using the raw key).
	decryptedBody, err := util.AESGCMDecrypt(response.Body, aesKey)
	require.NoError(t, err)
	assert.Equal(t, expectedBody, string(decryptedBody))
}

func TestHTTPEnclaveApp_Execute_NoEncryptionWithoutKey(t *testing.T) {
	expectedBody := `{"status":"ok"}`
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(expectedBody)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	request := &enclavetypes.Request{
		Method: http.MethodGet,
		Url:    "https://example.com/api",
	}
	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	// No AES key in secretsMap.
	secretsMap := map[string][]byte{
		"some_other_secret": []byte("value"),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())
	require.Nil(t, execError)
	require.NotNil(t, output)

	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)

	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
	// Body should be plaintext since no AES key was provided.
	assert.Equal(t, expectedBody, string(response.Body))
}

func TestHTTPEnclaveApp_Execute_AESGCMRoundTrip(t *testing.T) {
	// End-to-end test: encrypt in app, unmarshal proto, decrypt body, verify original.
	originalBody := `{"prices":[100.5,200.3,300.1]}`
	mockClient := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(originalBody)),
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Request-Id": []string{"abc123"},
			},
		}, nil
	})

	app := NewHTTPEnclaveApp(mockClient)

	request := &enclavetypes.Request{
		Method:        http.MethodGet,
		Url:           "https://example.com/api",
		EncryptOutput: true,
	}
	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	aesKey := make([]byte, 32)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)
	aesKeyHex := []byte(hex.EncodeToString(aesKey))

	secretsMap := map[string][]byte{
		types.AESGCMEncryptionKey: aesKeyHex,
		"api_key":                 []byte("my-api-key"),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())
	require.Nil(t, execError)
	require.NotNil(t, output)

	// Step 1: Unmarshal proto — headers and status should be readable.
	var response enclavetypes.Response
	err = proto.Unmarshal(output, &response)
	require.NoError(t, err)

	assert.Equal(t, uint32(http.StatusOK), response.StatusCode)
	require.NotEmpty(t, response.MultiHeaders)

	// Verify headers are plaintext.
	require.Contains(t, response.MultiHeaders, "Content-Type")
	assert.Equal(t, []string{"application/json"}, response.MultiHeaders["Content-Type"].Values)
	require.Contains(t, response.MultiHeaders, "X-Request-Id")
	assert.Equal(t, []string{"abc123"}, response.MultiHeaders["X-Request-Id"].Values)

	// Step 2: Decrypt body using the raw key.
	decrypted, err := util.AESGCMDecrypt(response.Body, aesKey)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(decrypted))
}

func TestHTTPEnclaveApp_Execute_EncryptOutputTrueWithoutKey(t *testing.T) {

	app := NewHTTPEnclaveApp(nil)

	request := &enclavetypes.Request{
		Method:        http.MethodGet,
		Url:           "https://example.com/api",
		EncryptOutput: true,
	}
	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	// No AES key in secrets.
	secretsMap := map[string][]byte{
		"some_secret": []byte("value"),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())

	require.NotNil(t, execError)
	assert.Nil(t, output)
	assert.Equal(t, http.StatusBadRequest, execError.Code)
	assert.Contains(t, execError.Error, types.ErrEncryptionRequestedNoKey)
}

func TestHTTPEnclaveApp_Execute_EncryptOutputFalseWithKey(t *testing.T) {

	app := NewHTTPEnclaveApp(nil)

	request := &enclavetypes.Request{
		Method:        http.MethodGet,
		Url:           "https://example.com/api",
		EncryptOutput: false,
	}
	inputDataBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	// AES key present but encrypt_output is false.
	aesKey := make([]byte, 32)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	secretsMap := map[string][]byte{
		types.AESGCMEncryptionKey: []byte(hex.EncodeToString(aesKey)),
	}

	var requestID [32]byte
	copy(requestID[:], "request_id")
	output, execError := app.Execute(requestID, types.AppIDConfidentialHTTP, inputDataBytes, secretsMap, emitter.NewNoOpEmitter())

	require.NotNil(t, execError)
	assert.Nil(t, output)
	assert.Equal(t, http.StatusBadRequest, execError.Code)
	assert.Contains(t, execError.Error, types.ErrKeyPresentNoEncryption)
}
