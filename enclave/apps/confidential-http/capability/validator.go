package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	confhttptypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
)

// Validator handles validation of HTTP requests and responses with proper limiters
type Validator struct {
	lggr                     logger.SugaredLogger
	responseSizeLimiter      limits.BoundLimiter[config.Size]
	requestSizeLimiter       limits.BoundLimiter[config.Size]
	connectionTimeoutLimiter limits.BoundLimiter[time.Duration]
}

// NewValidator creates a new Validator with initialized limiters
func NewValidator(lggr logger.Logger, limitsFactory limits.Factory) (*Validator, error) {
	responseSizeLimiter, err := limits.MakeUpperBoundLimiter(limitsFactory, cresettings.Default.PerWorkflow.ConfidentialHTTP.ResponseSizeLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create response size limiter: %w", err)
	}

	requestSizeLimiter, err := limits.MakeUpperBoundLimiter(limitsFactory, cresettings.Default.PerWorkflow.ConfidentialHTTP.RequestSizeLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create request size limiter: %w", err)
	}

	connectionTimeoutLimiter, err := limits.MakeUpperBoundLimiter(limitsFactory, cresettings.Default.PerWorkflow.ConfidentialHTTP.ConnectionTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection timeout limiter: %w", err)
	}

	return &Validator{
		lggr:                     logger.Sugared(logger.Named(lggr, "Validator")),
		responseSizeLimiter:      responseSizeLimiter,
		requestSizeLimiter:       requestSizeLimiter,
		connectionTimeoutLimiter: connectionTimeoutLimiter,
	}, nil
}

// ValidateRequest validates the HTTP request fields and applies default values where necessary.
func (v *Validator) ValidateRequest(ctx context.Context, input *confhttptypes.ConfidentialHTTPRequest) error {
	if input == nil {
		return errors.New("input cannot be nil")
	}

	err := v.validateInputWithLimiters(ctx, input)
	if err != nil {
		return errors.New("input validation failed: " + err.Error())
	}
	return nil
}

// validateInputWithLimiters validates input using bound limiters instead of config limits
func (v *Validator) validateInputWithLimiters(ctx context.Context, input *confhttptypes.ConfidentialHTTPRequest) error {
	if input == nil {
		return errors.New("input cannot be nil")
	}
	marshaled, err := json.Marshal(input.Request)
	if err != nil {
		errStr := "failed to marshal request for size calculation: " + err.Error()
		v.lggr.Error(errStr)
		return errors.New(errStr)
	}

	requestSize := config.Size(len(marshaled))
	if err = v.requestSizeLimiter.Check(ctx, requestSize); err != nil {
		errStr := "failed request size check: " + err.Error()
		v.lggr.Error(errStr)
		return errors.New(errStr)
	}
	// Validate connection timeout (use zero duration if not provided).
	var d time.Duration
	if input != nil && input.Request != nil && input.Request.Timeout != nil {
		d = input.Request.Timeout.AsDuration()
	} else {
		d = 0
	}

	if err = v.connectionTimeoutLimiter.Check(ctx, d); err != nil {
		errStr := "failed connection timeout check: " + err.Error()
		v.lggr.Error(errStr)
		return errors.New(errStr)
	}
	return nil
}

// ValidateResponseSize checks if the response size is within limits
func (v *Validator) ValidateResponseSize(ctx context.Context, response []byte) error {
	return v.responseSizeLimiter.Check(ctx, config.SizeOf(response))
}

func (v *Validator) Close() error {
	err := v.responseSizeLimiter.Close()
	if err != nil {
		return err
	}
	err = v.connectionTimeoutLimiter.Close()
	if err != nil {
		return err
	}
	return v.requestSizeLimiter.Close()
}
