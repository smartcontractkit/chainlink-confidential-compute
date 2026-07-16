package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	texttemplate "text/template"

	enclavetypes "github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"google.golang.org/protobuf/proto"
)

const maxResponseBytes = types.MaxHTTPResponseBodyBytes

// httpEnclaveApp is an implementation of the EnclaveApp interface that processes HTTP requests
// using some injected secrets. These secrets may be applied to the request headers or body,
// and are not revealed to any entity besides the enclave.
type httpEnclaveApp struct {
	httpClient   types.HTTPClient
	newTLSClient func(*tls.Config) types.HTTPClient
}

var _ types.EnclaveApp = (*httpEnclaveApp)(nil)

func NewHTTPEnclaveApp(httpClient types.HTTPClient) types.EnclaveApp {
	if httpClient == nil {
		httpClient = util.NewRestrictedHTTPClient()
	}
	return &httpEnclaveApp{
		httpClient: httpClient,
		newTLSClient: func(tlsCfg *tls.Config) types.HTTPClient {
			return util.NewRestrictedHTTPClientWithTLS(tlsCfg)
		},
	}
}

func (a *httpEnclaveApp) Execute(requestID [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter, _ ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
	if appID != types.AppIDConfidentialHTTP {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("invalid app ID: expected %s, got %s", types.AppIDConfidentialHTTP, appID),
			Code:  http.StatusBadRequest,
		}
	}

	var request enclavetypes.Request
	err := proto.Unmarshal(inputData, &request)
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("unable to unmarshal request data: %s", err.Error()),
			Code:  http.StatusBadRequest,
		}
	}

	// Validate encrypt_output against AES-GCM key presence.
	_, hasAESKey := secretsMap[types.AESGCMEncryptionKey]
	if request.EncryptOutput && !hasAESKey {
		return nil, &types.ExecuteError{
			Error: types.ErrEncryptionRequestedNoKey,
			Code:  http.StatusBadRequest,
		}
	}
	if !request.EncryptOutput && hasAESKey {
		return nil, &types.ExecuteError{
			Error: types.ErrKeyPresentNoEncryption,
			Code:  http.StatusBadRequest,
		}
	}

	requests := []*enclavetypes.Request{&request}

	for i, template := range requests {
		if template.Method == "" {
			return nil, &types.ExecuteError{
				Error: fmt.Sprintf("template at index %d is missing required http method. have: %s, %v, %s, %s", i, template.Body, template.MultiHeaders, template.Url, template.Method),
				Code:  http.StatusBadRequest,
			}
		}
	}

	httpBatchStart := time.Now()
	emitter.Emit("http_batch_started", map[string]any{
		"num_requests": len(requests),
	})

	var wg sync.WaitGroup
	type result struct {
		response *enclavetypes.Response
		err      error
		code     int
		index    int
	}
	resultsChan := make(chan *result, len(requests))

	for i, template := range requests {
		wg.Add(1)
		go func(index int, tmpl *enclavetypes.Request) {
			defer wg.Done()
			templateData := make(map[string]interface{})
			for k, v := range tmpl.TemplatePublicValues {
				templateData[k] = v
			}

			for k, v := range secretsMap {
				// Skip the AES-GCM encryption key — it's binary and used for
				// output encryption, not for template substitution.
				if k == types.AESGCMEncryptionKey {
					continue
				}
				if _, exists := templateData[k]; exists {
					resultsChan <- &result{
						err:   fmt.Errorf("public input and secret input have the same key: %s", k),
						index: index,
						code:  http.StatusBadRequest,
					}
					return
				}
				if !utf8.Valid(v) {
					resultsChan <- &result{
						err:   fmt.Errorf("secret value for key %s is not valid utf8", k),
						index: index,
						code:  http.StatusBadRequest,
					}
					return
				}
				templateData[k] = string(v)
			}

			httpResp, err := a.executeHTTPRequest(tmpl, templateData)
			resultsChan <- &result{response: &httpResp, err: err, index: index}
		}(i, template)
	}

	wg.Wait()
	close(resultsChan)

	responses := make([]*enclavetypes.Response, len(requests))
	errorMap := make(map[int]error)
	for res := range resultsChan {
		if res.err != nil {
			errorMap[res.index] = fmt.Errorf("error in request %d: %s", res.index, res.err.Error())
		} else {
			responses[res.index] = res.response
		}
	}
	if len(errorMap) > 0 {
		var errorStrings []string
		for i := 0; i < len(requests); i++ {
			if err, exists := errorMap[i]; exists {
				errorStrings = append(errorStrings, err.Error())
			}
		}
		return nil, &types.ExecuteError{
			Error: strings.Join(errorStrings, "; "),
			Code:  http.StatusBadRequest,
		}
	}

	// Encrypt response bodies if encryption was requested and AES-GCM key is present.
	// The AES key is stored as a hex-encoded string in the vault, so decode it first.
	if aesKeyHex, exists := secretsMap[types.AESGCMEncryptionKey]; exists && request.EncryptOutput {
		aesKey, err := hex.DecodeString(string(aesKeyHex))
		if err != nil {
			return nil, &types.ExecuteError{
				Error: fmt.Sprintf("failed to hex-decode AES-GCM key: %s", err.Error()),
				Code:  http.StatusBadRequest,
			}
		}
		for _, resp := range responses {
			if resp != nil {
				encrypted, err := util.AESGCMEncrypt(resp.Body, aesKey)
				if err != nil {
					return nil, &types.ExecuteError{
						Error: fmt.Sprintf("error encrypting response body: %s", err.Error()),
						Code:  http.StatusInternalServerError,
					}
				}
				resp.Body = encrypted
			}
		}
	}

	responseBytes, err := proto.Marshal(responses[0])
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("error marshaling combined responses: %s", err.Error()),
			Code:  http.StatusInternalServerError,
		}
	}

	emitter.Emit("http_batch_completed", map[string]any{
		"num_requests":     len(requests),
		"duration_seconds": time.Since(httpBatchStart).Seconds(),
	})

	return responseBytes, nil
}

// executeHTTPRequest executes a single HTTP request based on the given template and template data, and returns the response.
func (a *httpEnclaveApp) executeHTTPRequest(request *enclavetypes.Request, templateData map[string]interface{}) (enclavetypes.Response, error) {
	// Assign the template values to the request body, if a request body is used.
	var httpReq *http.Request
	var err error
	if util.MethodUsesBody(request.Method) {
		// Use type switch on the oneof field to correctly determine which body variant is set
		switch body := request.GetBody().(type) {
		case *enclavetypes.Request_BodyString:
			// BodyString variant: apply template processing
			processedBody := &bytes.Buffer{}
			bodyTmpl, err2 := texttemplate.New("body").Parse(body.BodyString)
			if err2 != nil {
				return enclavetypes.Response{}, fmt.Errorf("error parsing body template")
			}
			if err2 = bodyTmpl.Execute(processedBody, templateData); err2 != nil {
				return enclavetypes.Response{}, fmt.Errorf("error executing body template")
			}
			httpReq, err = http.NewRequest(request.Method, request.Url, processedBody)
		case *enclavetypes.Request_BodyBytes:
			// BodyBytes variant: use raw bytes directly (no template processing)
			httpReq, err = http.NewRequest(request.Method, request.Url, bytes.NewBuffer(body.BodyBytes))
		default:
			// No body set: send request with empty body
			httpReq, err = http.NewRequest(request.Method, request.Url, nil)
		}
	} else {
		httpReq, err = http.NewRequest(request.Method, request.Url, nil)
	}
	if err != nil {
		return enclavetypes.Response{}, fmt.Errorf("error creating http request")
	}

	// Apply all template values assigned to the request headers.
	for headerName, headerValues := range request.MultiHeaders {
		if headerValues == nil || headerName == types.AESGCMEncryptionKey {
			continue
		}
		for _, headerValueTemplate := range headerValues.Values {
			headerTmpl, err := texttemplate.New("header").Parse(headerValueTemplate)
			if err != nil {
				return enclavetypes.Response{}, fmt.Errorf("error parsing header template")
			}

			var processedHeader bytes.Buffer
			if err := headerTmpl.Execute(&processedHeader, templateData); err != nil {
				return enclavetypes.Response{}, fmt.Errorf("error executing header template")
			}

			httpReq.Header.Add(headerName, processedHeader.String())
		}
	}

	// If a custom root CA certificate is specified by the client, use it.
	var client = a.httpClient
	if len(request.CustomRootCaCertPem) > 0 {
		certPool := x509.NewCertPool()
		if certPool.AppendCertsFromPEM(request.CustomRootCaCertPem) {
			tlsConfig := &tls.Config{
				RootCAs: certPool,
			}
			client = a.newTLSClient(tlsConfig)
		} else {
			return enclavetypes.Response{}, fmt.Errorf("error parsing custom root CA certificate")
		}
	}

	var timeout = types.DefaultEnclaveRequestTimeout
	if request.Timeout != nil && request.Timeout.AsDuration() > 0 {
		timeout = request.Timeout.AsDuration()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	httpResp, err := client.Do(httpReq)
	if err != nil {
		// Timeout (504), DNS NXDOMAIN (400), and SSRF-policy blocks (400) are
		// caller-facing conditions returned as HTTP status responses rather than
		// enclave failures. See util.ClassifyOutboundHTTPError.
		if he := util.ClassifyOutboundHTTPError(err); he != nil {
			return enclavetypes.Response{
				StatusCode: uint32(he.StatusCode),
				Body:       []byte(he.Body),
			}, nil
		}
		// The error returned by http.DefaultClient.Do call should not leak headers or the request body.
		// Developers passing in custom HTTP clients to this application should ensure the same behavior.
		return enclavetypes.Response{}, fmt.Errorf("error making http request: %v", err)
	}
	defer util.SafeClose(httpResp)
	limitedReader := io.LimitReader(httpResp.Body, maxResponseBytes+1)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return enclavetypes.Response{}, fmt.Errorf("error reading http response: %v", err)
	}
	if len(respBody) > maxResponseBytes {
		return enclavetypes.Response{}, fmt.Errorf("%s of %d bytes", types.ErrResponseBodyTooLarge, maxResponseBytes)
	}

	return enclavetypes.Response{
		StatusCode:   uint32(httpResp.StatusCode),
		Body:         respBody,
		MultiHeaders: convertHeaders(httpResp.Header),
	}, nil
}

// convertHeaders converts http.Header (map[string][]string) to map[string]*HeaderValues.
func convertHeaders(h http.Header) map[string]*enclavetypes.HeaderValues {
	if len(h) == 0 {
		return nil
	}
	result := make(map[string]*enclavetypes.HeaderValues, len(h))
	for name, values := range h {
		result[name] = &enclavetypes.HeaderValues{Values: values}
	}
	return result
}
