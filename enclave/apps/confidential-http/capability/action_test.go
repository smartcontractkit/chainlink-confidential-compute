package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	confhttptypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
)

// TestSendRequest_InputValidationFailure_ClassifiedAsUserError verifies that when the validator
// rejects a ConfidentialHTTPRequest (e.g. request size > limit), the returned caperrors.Error has
// OriginUser, code InvalidArgument, and VisibilityPublic. This routes the failure to
// platform_engine_capabilities_user_errors instead of _failures, taking workflow-author bugs off
// the system-error alert path. Also asserts that the "input validation failed:" prefix is not
// double-applied (the validator already adds it; the action passes err through directly).
func TestSendRequest_InputValidationFailure_ClassifiedAsUserError(t *testing.T) {
	lg := logger.Test(t)

	// Request size limiter rejects every check, simulating a workflow that exceeded its
	// PerWorkflow.ConfidentialHTTP.RequestSizeLimit.
	reqLimiter := &fakeSizeLimiter{
		checkFunc: func(_ context.Context, _ config.Size) error {
			return errors.New("size limit exceeded")
		},
	}

	v := &Validator{
		lggr:                     logger.Sugared(lg),
		responseSizeLimiter:      (limits.BoundLimiter[config.Size])(nil),
		requestSizeLimiter:       limits.BoundLimiter[config.Size](reqLimiter),
		connectionTimeoutLimiter: limits.BoundLimiter[time.Duration](&fakeDurationLimiter{}),
	}

	action := &ConfidentialHttpAction{
		lggr:      logger.Sugared(lg),
		validator: v,
	}

	input := &confhttptypes.ConfidentialHTTPRequest{
		Request: &confhttptypes.HTTPRequest{
			Url:    "https://example.com",
			Method: "GET",
		},
	}

	_, capErr := action.SendRequest(context.Background(), capabilities.RequestMetadata{}, input)
	require.NotNil(t, capErr, "expected typed error from SendRequest")

	assert.Equal(t, caperrors.OriginUser, capErr.Origin())
	assert.Equal(t, caperrors.InvalidArgument, capErr.Code())
	assert.Equal(t, caperrors.VisibilityPublic, capErr.Visibility())

	assert.Contains(t, capErr.Error(), "input validation failed: failed request size check: size limit exceeded")
	assert.NotContains(t, capErr.Error(), "input validation failed: input validation failed:",
		"validator already prefixes 'input validation failed: '; action should not double-prefix")
}
