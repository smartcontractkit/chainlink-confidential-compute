package framework

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// TestApplyLimitSettings_PerCapability guards the split that lets one
// capability's limits change without moving the other: a capability-specific
// value wins for its own capability, while every other capability keeps
// resolving to the shared ConfidentialCompute value.
func TestApplyLimitSettings_PerCapability(t *testing.T) {
	g, err := settings.NewJSONGetter([]byte(`{
		"global": {
			"ConfidentialCompute": {
				"GlobalRate": "100rps:10000",
				"MaxRetries": "5",
				"EnclaveRefreshInterval": "10s",
				"PublicKeyCache": {"TTL": "5m"},
				"Session": {"HeaderName": "Shared-Session"},
				"HTTP": {
					"GlobalRate": "7rps:70",
					"EnclaveRefreshInterval": "30s",
					"PublicKeyCache": {"TTL": "1m"},
					"Session": {"HeaderName": "HTTP-Session"}
				}
			}
		}
	}`))
	require.NoError(t, err)

	apply := func(capabilityID string) *ParsedConfig {
		parsed := &ParsedConfig{}
		exec := &RealExecutor{capabilityID: capabilityID, limitsFactory: limits.Factory{Settings: g}}
		exec.applyLimitSettings(t.Context(), parsed)
		return parsed
	}

	t.Run("specific capability takes its own value", func(t *testing.T) {
		parsed := apply(types.AppIDConfidentialHTTP)
		assert.Equal(t, float64(7), parsed.GlobalRPS)
		assert.Equal(t, 70, parsed.GlobalBurst)
	})

	t.Run("other capability keeps the shared value", func(t *testing.T) {
		parsed := apply(types.AppIDConfidentialWorkflows)
		assert.Equal(t, float64(100), parsed.GlobalRPS)
		assert.Equal(t, 10000, parsed.GlobalBurst)
	})

	t.Run("unset settings fall back to the shared value", func(t *testing.T) {
		for _, capabilityID := range []string{types.AppIDConfidentialHTTP, types.AppIDConfidentialWorkflows} {
			parsed := apply(capabilityID)
			assert.Equal(t, 5, parsed.MaxRetries, capabilityID)
		}
	})

	t.Run("client-side settings resolve per capability", func(t *testing.T) {
		http := apply(types.AppIDConfidentialHTTP)
		assert.Equal(t, 30*time.Second, http.EnclaveRefreshInterval)
		assert.Equal(t, time.Minute, http.CacheConfig.DefaultTTL)
		assert.Equal(t, "HTTP-Session", http.SessionConfig.SessionHeaderName)

		workflows := apply(types.AppIDConfidentialWorkflows)
		assert.Equal(t, 10*time.Second, workflows.EnclaveRefreshInterval)
		assert.Equal(t, 5*time.Minute, workflows.CacheConfig.DefaultTTL)
		assert.Equal(t, "Shared-Session", workflows.SessionConfig.SessionHeaderName)
	})

	t.Run("unknown capability uses the shared values", func(t *testing.T) {
		parsed := apply("some-other-capability@1.0.0")
		assert.Equal(t, float64(100), parsed.GlobalRPS)
		assert.Equal(t, 5, parsed.MaxRetries)
	})
}
