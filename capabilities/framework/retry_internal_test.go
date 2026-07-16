package framework

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newTestExecutor builds a minimal *RealExecutor with only the fields retryWithBackoff touches.
// RetryBackoffSeconds=0 keeps the test fast (no real delays between attempts).
func newTestExecutor(t *testing.T, maxRetries int) *RealExecutor {
	return &RealExecutor{
		lggr: logger.Test(t),
		capConfig: &ParsedConfig{
			MaxRetries:          maxRetries,
			RetryBackoffSeconds: 0,
		},
	}
}

// TestRetryWithBackoff_UserError_ShortCircuits verifies that a typed user error returned by fn
// causes retryWithBackoff to exit immediately. The fix routes workflow-author bugs off the
// retry path so they don't burn capability-DON capacity or fill level=error logs.
func TestRetryWithBackoff_UserError_ShortCircuits(t *testing.T) {
	e := newTestExecutor(t, 3)

	calls := 0
	userErr := caperrors.NewPublicUserError(errors.New("workflow misconfigured"), caperrors.InvalidArgument)
	err := e.retryWithBackoff(context.Background(), func() error {
		calls++
		return userErr
	})

	assert.Equal(t, 1, calls, "user error should not be retried")
	require.Error(t, err)

	// The returned error must still be the typed user error so callers can route it correctly.
	var capErr caperrors.Error
	require.True(t, errors.As(err, &capErr), "returned error should still unwrap to caperrors.Error")
	assert.Equal(t, caperrors.OriginUser, capErr.Origin())
	assert.Equal(t, caperrors.InvalidArgument, capErr.Code())
}

// TestRetryWithBackoff_SystemError_RetriesUpToMax verifies that a typed system error still
// retries the full MaxRetries times. The user-error short-circuit must not affect existing
// retry behavior for infrastructure failures.
func TestRetryWithBackoff_SystemError_RetriesUpToMax(t *testing.T) {
	e := newTestExecutor(t, 3)

	calls := 0
	systemErr := caperrors.NewPublicSystemError(errors.New("transient backend failure"), caperrors.Unavailable)
	err := e.retryWithBackoff(context.Background(), func() error {
		calls++
		return systemErr
	})

	assert.Equal(t, 3, calls, "system error should retry MaxRetries times")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed after 3 retries")
}

// TestRetryWithBackoff_UntypedError_RetriesUpToMax verifies that errors that don't unwrap to
// a caperrors.Error are treated as system errors and retried. Without this, any non-typed
// error in fn would accidentally short-circuit and bypass retries.
func TestRetryWithBackoff_UntypedError_RetriesUpToMax(t *testing.T) {
	e := newTestExecutor(t, 3)

	calls := 0
	untypedErr := errors.New("plain error")
	err := e.retryWithBackoff(context.Background(), func() error {
		calls++
		return untypedErr
	})

	assert.Equal(t, 3, calls, "untyped error should retry MaxRetries times")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed after 3 retries")
}

// TestRetryWithBackoff_Success_NoRetry verifies the existing happy-path semantics: fn returning
// nil exits the loop immediately on the first attempt.
func TestRetryWithBackoff_Success_NoRetry(t *testing.T) {
	e := newTestExecutor(t, 3)

	calls := 0
	err := e.retryWithBackoff(context.Background(), func() error {
		calls++
		return nil
	})

	assert.Equal(t, 1, calls)
	assert.NoError(t, err)
}
