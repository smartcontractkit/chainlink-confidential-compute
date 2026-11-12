package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type settingsTestApp struct {
	*mockEnclaveApp
	enforced atomic.Bool
}

func (a *settingsTestApp) InjectSettings(raw json.RawMessage) error {
	var settings struct {
		Enforced bool `json:"enforceCRELimits"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return err
	}
	a.enforced.Store(settings.Enforced)
	return nil
}

func (a *settingsTestApp) SettingsStatus() map[string]any {
	return map[string]any{"enforceCRELimits": a.enforced.Load()}
}

func TestSettingsStatus(t *testing.T) {
	app := &settingsTestApp{mockEnclaveApp: newMockEnclaveApp()}
	url := setupTestServerWithMockApp(t, app)
	for _, enabled := range []bool{false, true, false} {
		payload := `{"enforceCRELimits":false,"storageKey":"secret"}`
		if enabled {
			payload = `{"enforceCRELimits":true,"storageKey":"secret"}`
		}
		resp, err := http.Post(url+"/settings", "application/json", strings.NewReader(payload))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		resp, err = http.Get(url + "/settings")
		require.NoError(t, err)
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		var status map[string]any
		require.NoError(t, json.Unmarshal(raw, &status))
		assert.Equal(t, map[string]any{"enforceCRELimits": enabled}, status)
		assert.NotContains(t, string(raw), "secret")
	}
}

func TestSettingsStatus_UnsupportedApp(t *testing.T) {
	url := setupTestServerWithMockApp(t, newMockEnclaveApp())
	resp, err := http.Get(url + "/settings")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}
