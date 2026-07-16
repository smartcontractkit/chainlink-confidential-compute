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

	"github.com/smartcontractkit/confidential-compute/capabilities/framework"
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

func TestApplyLimitSettings_OverlaysExecutorConfigSettings(t *testing.T) {
	t.Parallel()

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

	assert.True(t, parsed.InsecureSkipTLSVerify, "deprecated job-spec override wins for InsecureSkipTLSVerify")
	assert.Equal(t, 30*time.Second, parsed.EnclaveRefreshInterval, "deprecated job-spec override wins for refresh interval")
	assert.False(t, parsed.CacheConfig.EnableCache, "deprecated job-spec override wins for EnableCache")
	assert.Equal(t, 120*time.Second, parsed.CacheConfig.DefaultTTL, "deprecated job-spec override wins for CacheTTLSeconds")
	assert.False(t, parsed.SessionConfig.EnableSessionPersistence, "deprecated job-spec override wins for EnableSessionPersistence")
	assert.Equal(t, "Custom-Session", parsed.SessionConfig.SessionHeaderName, "deprecated job-spec override wins for SessionHeaderName")
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

	parsed, err := framework.ParseConfig(`{"EnclaveRequestTimeoutSeconds": 45, "PublicKeyRequestTimeoutSeconds": 9}`)
	require.NoError(t, err)

	exec := framework.NewTestExecutor(
		logger.Test(t), getMockKeystore(), &MockEnclaveClient{}, framework.VaultDON{}, NewMockMetrics(),
		getDefaultRateLimiter(), 1, 0, "test-capability-id", false, TEST_NODE_ID,
		getMockCapabilitiesRegistry(t, framework.VaultDON{}),
	)
	exec.SetLimitsFactoryForTesting(limits.Factory{Settings: &fakeTimeoutGetter{value: "100ms"}})

	exec.ApplyLimitSettingsForTesting(context.Background(), parsed)

	assert.Equal(t, 45*time.Second, parsed.EnclaveRequestTimeout, "deprecated job-spec override wins for enclave timeout")
	assert.Equal(t, 9*time.Second, parsed.PublicKeyRequestTimeout, "deprecated job-spec override wins for public key timeout")
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
