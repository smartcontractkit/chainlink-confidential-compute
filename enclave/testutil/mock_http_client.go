// Package testutil provides shared enclave test doubles.
package testutil

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

	if m.RequestsReceived == nil {
		m.RequestsReceived = make([]*http.Request, 0)
	}

	reqCopy := *req
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		if err := req.Body.Close(); err != nil {
			return nil, err
		}
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	m.RequestsReceived = append(m.RequestsReceived, &reqCopy)

	if m.CustomResponseFunc != nil {
		return m.CustomResponseFunc(req)
	}
	if m.Response == nil {
		return nil, m.Err
	}

	respCopy := *m.Response
	if m.Response.Body != nil {
		bodyBytes, err := io.ReadAll(m.Response.Body)
		if err != nil {
			return nil, err
		}
		if err := m.Response.Body.Close(); err != nil {
			return nil, err
		}
		m.Response.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		respCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	return &respCopy, m.Err
}

func (m *MockHTTPClient) SetResponse(resp *http.Response, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Response = resp
	m.Err = err
}
