// This package provides a lightweight mock implementation of the HTTP client interface.
package mocks

import (
	"bytes"
	"io"
	"net/http"
	"sync"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

type MockHTTPClient struct {
	mu                 sync.Mutex
	Response           *http.Response
	Err                error
	CustomResponseFunc func(*http.Request) (*http.Response, error)
	RequestsReceived   []*http.Request
}

func NewMockHTTPClient(response *http.Response, err error) types.HTTPClient {
	return &MockHTTPClient{
		Response:         response,
		Err:              err,
		RequestsReceived: make([]*http.Request, 0),
	}
}

func NewMockHTTPClientWithCustomResponse(responseFunc func(*http.Request) (*http.Response, error)) types.HTTPClient {
	return &MockHTTPClient{
		CustomResponseFunc: responseFunc,
		RequestsReceived:   make([]*http.Request, 0),
	}
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the request for inspection.
	if m.RequestsReceived == nil {
		m.RequestsReceived = make([]*http.Request, 0)
	}

	// Clone the request to avoid EOF errors on subsequent reads.
	reqCopy := *req

	// Save content of body if present.
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		err := req.Body.Close()
		if err != nil {
			return nil, err
		}
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		// Reset original request body
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	m.RequestsReceived = append(m.RequestsReceived, &reqCopy)

	if m.CustomResponseFunc != nil {
		return m.CustomResponseFunc(req)
	}

	// If standard response is set, return a copy with a fresh body.
	if m.Response != nil {
		respCopy := *m.Response
		if m.Response.Body != nil {
			bodyBytes, err := io.ReadAll(m.Response.Body)
			if err != nil {
				return nil, err
			}
			err = m.Response.Body.Close()
			if err != nil {
				return nil, err
			}
			// Reset original response body
			m.Response.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			// Create copy with fresh body
			respCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return &respCopy, m.Err
	}

	return m.Response, m.Err
}

func (m *MockHTTPClient) SetResponse(resp *http.Response, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Response = resp
	m.Err = err
}
