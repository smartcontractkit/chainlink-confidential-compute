package framework_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework"
)

type fakeTimeoutGetter struct {
	value string
	err   error
	calls atomic.Int32
}

func (f *fakeTimeoutGetter) GetScoped(context.Context, settings.Scope, string) (string, error) {
	f.calls.Add(1)
	return f.value, f.err
}

func TestApplyLimitSettings_IgnoresDeprecatedJobSpecConfig(t *testing.T) {
	t.Parallel()

	// The job-spec sets several deprecated Config fields, but they are no longer read:
	// cresettings are authoritative, so applyLimitSettings resolves the limits defaults
	// and the job-spec values are ignored.
	parsed, err := framework.ParseConfig(`{
		"InsecureSkipTLSVerify": true,
		"EnclaveRefreshIntervalSeconds": 30,
		"EnableCache": false,
		"CacheTTLSeconds": 120,
		"EnableSessionPersistence": false,
		"SessionHeaderName": "Custom-Session"
	}`)
	require.NoError(t, err)

	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.ApplyLimitSettingsForTesting(context.Background(), parsed)

	assert.False(t, parsed.InsecureSkipTLSVerify, "job-spec value ignored; cresettings default wins")
	assert.Equal(t, 10*time.Second, parsed.EnclaveRefreshInterval, "job-spec value ignored; cresettings default wins")
	assert.True(t, parsed.CacheConfig.EnableCache, "job-spec value ignored; cresettings default wins")
	assert.Equal(t, 5*time.Minute, parsed.CacheConfig.DefaultTTL, "job-spec value ignored; cresettings default wins")
	assert.True(t, parsed.SessionConfig.EnableSessionPersistence, "job-spec value ignored; cresettings default wins")
	assert.Equal(t, "Sticky-Session-A", parsed.SessionConfig.SessionHeaderName, "job-spec value ignored; cresettings default wins")
}

func TestApplyLimitSettings_UsesLimitsDefaultsWhenJobSpecUnset(t *testing.T) {
	t.Parallel()

	parsed, err := framework.ParseConfig("{}")
	require.NoError(t, err)

	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.ApplyLimitSettingsForTesting(context.Background(), parsed)

	assert.False(t, parsed.InsecureSkipTLSVerify)
	assert.Equal(t, 10*time.Second, parsed.EnclaveRefreshInterval)
	assert.True(t, parsed.CacheConfig.EnableCache)
	assert.Equal(t, 5*time.Minute, parsed.CacheConfig.DefaultTTL)
	assert.True(t, parsed.SessionConfig.EnableSessionPersistence)
	assert.Equal(t, "Sticky-Session-A", parsed.SessionConfig.SessionHeaderName)
}

func TestApplyLimitSettings_OverlaysRequestTimeouts(t *testing.T) {
	t.Parallel()

	// Even though the job-spec sets timeouts, they are ignored; the timeouts come from
	// the limits settings (cresettings) resolved in applyLimitSettings.
	parsed, err := framework.ParseConfig(`{"EnclaveRequestTimeoutSeconds": 45, "PublicKeyRequestTimeoutSeconds": 9}`)
	require.NoError(t, err)

	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.SetLimitsFactoryForTesting(limits.Factory{Settings: &fakeTimeoutGetter{value: "100ms"}})

	exec.ApplyLimitSettingsForTesting(context.Background(), parsed)

	assert.Equal(t, 100*time.Millisecond, parsed.EnclaveRequestTimeout, "timeout comes from limits, not the job-spec")
	assert.Equal(t, 100*time.Millisecond, parsed.PublicKeyRequestTimeout, "timeout comes from limits, not the job-spec")
}

func TestResolveRequestTimeout_ReadsLimitsPerCall(t *testing.T) {
	t.Parallel()

	getter := &fakeTimeoutGetter{value: "100ms"}
	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.SetLimitsFactoryForTesting(limits.Factory{Settings: getter})
	parsed, err := framework.ParseConfig("{}")
	require.NoError(t, err)
	exec.SetParsedConfigForTesting(parsed)

	first, err := exec.ResolveRequestTimeoutForTesting(context.Background(), false)
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, first)
	second, err := exec.ResolveRequestTimeoutForTesting(context.Background(), false)
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, second)
	assert.Equal(t, int32(2), getter.calls.Load(), "limits should be re-read on each call")
}

func TestResolveRequestTimeout_PropagatesLimitsError(t *testing.T) {
	t.Parallel()

	getter := &fakeTimeoutGetter{err: errors.New("settings unavailable")}
	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.SetLimitsFactoryForTesting(limits.Factory{Settings: getter})

	_, err := exec.ResolveRequestTimeoutForTesting(context.Background(), false)
	require.Error(t, err)
	assert.ErrorContains(t, err, "resolve enclave request timeout from limits")
	assert.ErrorContains(t, err, "settings unavailable")
}

func TestResolveRequestTimeout_UsesPublicKeyLimit(t *testing.T) {
	t.Parallel()

	getter := &fakeTimeoutGetter{value: "250ms"}
	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.SetLimitsFactoryForTesting(limits.Factory{Settings: getter})
	parsed, err := framework.ParseConfig("{}")
	require.NoError(t, err)
	exec.SetParsedConfigForTesting(parsed)

	timeout, err := exec.ResolveRequestTimeoutForTesting(context.Background(), true)
	require.NoError(t, err)
	assert.Equal(t, 250*time.Millisecond, timeout)
}
