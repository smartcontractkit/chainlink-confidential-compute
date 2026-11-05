package framework

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// newRequestTimeoutResolver returns a pool callback that resolves enclave and
// public-key request timeouts on each call from the limits framework and
// deprecated job-spec overrides.
func (e *RealExecutor) newRequestTimeoutResolver() func(ctx context.Context, publicKey bool) (time.Duration, error) {
	return e.resolveRequestTimeout
}

// resolveRequestTimeout reads the authoritative limits value on each call so a
// limit change takes effect without re-initializing the pool. A deprecated
// job-spec override still wins when set.
func (e *RealExecutor) resolveRequestTimeout(ctx context.Context, publicKey bool) (time.Duration, error) {
	g := e.limitsFactory.Settings
	cfg := e.getCapConfig()
	cc := cresettings.Default.ConfidentialCompute
	capCC := e.capabilityLimits()

	if publicKey {
		timeout, err := capCC.PublicKeyRequestTimeout.GetOrDefaultWithFallback(ctx, g, cc.PublicKeyRequestTimeout)
		if err != nil {
			return 0, fmt.Errorf("resolve public key request timeout from limits: %w", err)
		}
		if cfg != nil && cfg.Config.PublicKeyRequestTimeoutSeconds != nil {
			return time.Duration(*cfg.Config.PublicKeyRequestTimeoutSeconds) * time.Second, nil
		}
		if timeout > 0 {
			return timeout, nil
		}
		return types.DefaultPublicKeyRequestTimeout, nil
	}

	timeout, err := capCC.EnclaveRequestTimeout.GetOrDefaultWithFallback(ctx, g, cc.EnclaveRequestTimeout)
	if err != nil {
		return 0, fmt.Errorf("resolve enclave request timeout from limits: %w", err)
	}
	if cfg != nil && cfg.Config.EnclaveRequestTimeoutSeconds != nil {
		return time.Duration(*cfg.Config.EnclaveRequestTimeoutSeconds) * time.Second, nil
	}
	if timeout > 0 {
		return timeout, nil
	}
	return types.DefaultEnclaveRequestTimeout, nil
}
