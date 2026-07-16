package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"

	confhttptypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
)

// fake limiter for config.Size
type fakeSizeLimiter struct {
	checkFunc func(context.Context, config.Size) error
}

func (f *fakeSizeLimiter) Close() error {
	return nil
}
func (f *fakeSizeLimiter) Limit(ctx context.Context) (config.Size, error) {
	return config.Size(1), nil
}

func (f *fakeSizeLimiter) Check(ctx context.Context, s config.Size) error {
	if f.checkFunc == nil {
		return nil
	}
	return f.checkFunc(ctx, s)
}

// fake limiter for time.Duration
type fakeDurationLimiter struct {
	checkFunc func(context.Context, time.Duration) error
}

func (f *fakeDurationLimiter) Close() error {
	return nil
}
func (f *fakeDurationLimiter) Limit(ctx context.Context) (time.Duration, error) {
	return time.Duration(0), nil
}

func (f *fakeDurationLimiter) Check(ctx context.Context, d time.Duration) error {
	if f.checkFunc == nil {
		return nil
	}
	return f.checkFunc(ctx, d)
}

func TestValidatedRequest_NilInput_ReturnsError(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))
	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      (limits.BoundLimiter[config.Size])(nil),
		requestSizeLimiter:       (limits.BoundLimiter[config.Size])(nil),
		connectionTimeoutLimiter: (limits.BoundLimiter[time.Duration])(nil),
	}

	err := v.ValidateRequest(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected error for nil input, got nil")
	}
	if err.Error() != "input cannot be nil" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateResponseSize_Success(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))

	// Expect size 10
	respLimiter := &fakeSizeLimiter{
		checkFunc: func(_ context.Context, s config.Size) error {
			if s != config.Size(10) {
				return errors.New("unexpected size")
			}
			return nil
		},
	}

	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      limits.BoundLimiter[config.Size](respLimiter),
		requestSizeLimiter:       (limits.BoundLimiter[config.Size])(nil),
		connectionTimeoutLimiter: (limits.BoundLimiter[time.Duration])(nil),
	}

	err := v.ValidateResponseSize(context.Background(), make([]byte, 10))
	assert.NoError(t, err)
}

func TestValidateResponseSize_Failure(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))

	respLimiter := &fakeSizeLimiter{
		checkFunc: func(_ context.Context, _ config.Size) error {
			return errors.New("limit exceeded")
		},
	}

	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      limits.BoundLimiter[config.Size](respLimiter),
		requestSizeLimiter:       (limits.BoundLimiter[config.Size])(nil),
		connectionTimeoutLimiter: (limits.BoundLimiter[time.Duration])(nil),
	}

	err := v.ValidateResponseSize(context.Background(), []byte("payload"))
	assert.ErrorContains(t, err, "limit exceeded")
}

func TestValidateRequest_ConnectionTimeout_Success(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))

	// request size limiter should allow the request through
	reqLimiter := &fakeSizeLimiter{}

	// expect 2s timeout
	timeoutLimiter := &fakeDurationLimiter{
		checkFunc: func(_ context.Context, d time.Duration) error {
			if d != 2*time.Second {
				return errors.New("unexpected timeout")
			}
			return nil
		},
	}

	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      (limits.BoundLimiter[config.Size])(nil),
		requestSizeLimiter:       limits.BoundLimiter[config.Size](reqLimiter),
		connectionTimeoutLimiter: limits.BoundLimiter[time.Duration](timeoutLimiter),
	}

	input := &confhttptypes.ConfidentialHTTPRequest{
		Request: &confhttptypes.HTTPRequest{
			Timeout: durationpb.New(2 * time.Second),
		},
	}

	err := v.ValidateRequest(context.Background(), input)
	assert.NoError(t, err)
}

func TestValidateRequest_ConnectionTimeout_ZeroTimeout_Success(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))

	// request size limiter should allow the request through
	reqLimiter := &fakeSizeLimiter{}

	// expect zero duration when timeout is absent
	timeoutLimiter := &fakeDurationLimiter{
		checkFunc: func(_ context.Context, d time.Duration) error {
			if d != 0 {
				return errors.New("unexpected timeout")
			}
			return nil
		},
	}

	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      (limits.BoundLimiter[config.Size])(nil),
		requestSizeLimiter:       limits.BoundLimiter[config.Size](reqLimiter),
		connectionTimeoutLimiter: limits.BoundLimiter[time.Duration](timeoutLimiter),
	}

	// Request with nil Timeout -> zero duration
	input := &confhttptypes.ConfidentialHTTPRequest{
		Request: &confhttptypes.HTTPRequest{},
	}

	err := v.ValidateRequest(context.Background(), input)
	assert.NoError(t, err)
}

func TestValidateRequest_ConnectionTimeout_Failure(t *testing.T) {
	lg := logger.Sugared(logger.Test(t))

	// request size limiter should allow the request through
	reqLimiter := &fakeSizeLimiter{}

	timeoutLimiter := &fakeDurationLimiter{
		checkFunc: func(_ context.Context, _ time.Duration) error {
			return errors.New("timeout exceeded")
		},
	}

	v := &Validator{
		lggr:                     lg,
		responseSizeLimiter:      (limits.BoundLimiter[config.Size])(nil),
		requestSizeLimiter:       limits.BoundLimiter[config.Size](reqLimiter),
		connectionTimeoutLimiter: limits.BoundLimiter[time.Duration](timeoutLimiter),
	}

	input := &confhttptypes.ConfidentialHTTPRequest{
		Request: &confhttptypes.HTTPRequest{
			Timeout: durationpb.New(1 * time.Second),
		},
	}

	err := v.ValidateRequest(context.Background(), input)
	assert.ErrorContains(t, err, "timeout exceeded")
}
