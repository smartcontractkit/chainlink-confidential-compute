package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettingsProxy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			payload := `{"enforceCRELimits":false}`
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				assert.Equal(t, method, r.Method)
				assert.Equal(t, types.SettingsPath, r.URL.Path)
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, payload, string(body))
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(payload))}, nil
			})
			h := NewHostServer(t.Context(), &http.Client{Transport: transport})
			t.Cleanup(h.cancel)
			w := httptest.NewRecorder()
			h.handleInjectSettings(w, httptest.NewRequest(method, types.SettingsPath, strings.NewReader(payload)))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Equal(t, payload, w.Body.String())
		})
	}
}
