package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	wfpb "github.com/smartcontractkit/chainlink-protos/workflows/go/v2"
)

// panickingHelper panics from every method that the wrapper is expected to guard.
type panickingHelper struct{ panicWith any }

var _ host.ExecutionHelper = (*panickingHelper)(nil)

func (p *panickingHelper) CallCapability(context.Context, *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	panic(p.panicWith)
}
func (p *panickingHelper) GetSecrets(context.Context, *sdkpb.GetSecretsRequest) ([]*sdkpb.SecretResponse, error) {
	panic(p.panicWith)
}
func (p *panickingHelper) GetDONTime() (time.Time, error) { panic(p.panicWith) }
func (p *panickingHelper) EmitUserLog(string) error       { panic(p.panicWith) }
func (p *panickingHelper) GetWorkflowExecutionID() string { return "exec-1" }
func (p *panickingHelper) GetNodeTime() time.Time         { return time.Unix(42, 0) }
func (p *panickingHelper) EmitUserMetric(context.Context, *wfpb.WorkflowUserMetric) error {
	panic(p.panicWith)
}

// passthroughHelper records that each call reached the inner helper.
type passthroughHelper struct{ err error }

var _ host.ExecutionHelper = (*passthroughHelper)(nil)

func (p *passthroughHelper) CallCapability(context.Context, *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	return &sdkpb.CapabilityResponse{}, p.err
}
func (p *passthroughHelper) GetSecrets(context.Context, *sdkpb.GetSecretsRequest) ([]*sdkpb.SecretResponse, error) {
	return []*sdkpb.SecretResponse{{}}, p.err
}
func (p *passthroughHelper) GetDONTime() (time.Time, error) { return time.Unix(7, 0), p.err }
func (p *passthroughHelper) EmitUserLog(string) error       { return p.err }
func (p *passthroughHelper) GetWorkflowExecutionID() string { return "exec-1" }
func (p *passthroughHelper) GetNodeTime() time.Time         { return time.Unix(42, 0) }
func (p *passthroughHelper) EmitUserMetric(context.Context, *wfpb.WorkflowUserMetric) error {
	return p.err
}

// guardedCalls exercises every method the wrapper guards. Each returns only the
// error, so the table can assert uniformly.
func guardedCalls(h host.ExecutionHelper) map[string]func() error {
	return map[string]func() error{
		"CallCapability": func() error {
			_, err := h.CallCapability(context.Background(), &sdkpb.CapabilityRequest{Id: "cap"})
			return err
		},
		"GetSecrets": func() error {
			_, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{})
			return err
		},
	}
}

func TestPanicSafeExecutionHelper_ConvertsPanicToError(t *testing.T) {
	t.Parallel()

	for name, call := range guardedCalls(
		newPanicSafeExecutionHelper(&panickingHelper{panicWith: "boom"}, logger.Test(t)),
	) {
		t.Run(name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() { err = call() })
			require.Error(t, err)
			assert.Contains(t, err.Error(), "panic in "+name)
			assert.Contains(t, err.Error(), "boom")
		})
	}
}

// A nil-map write and a bad type assertion are the realistic shapes of this bug,
// and they panic with runtime.Error rather than a string.
func TestPanicSafeExecutionHelper_ConvertsRuntimePanicToError(t *testing.T) {
	t.Parallel()

	var nilMap map[string]string
	helper := newPanicSafeExecutionHelper(&runtimePanicHelper{write: func() { nilMap["k"] = "v" }}, logger.Test(t))

	_, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{Id: "cap"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in CallCapability")
	assert.Contains(t, err.Error(), "nil map")
}

type runtimePanicHelper struct {
	passthroughHelper
	write func()
}

func (r *runtimePanicHelper) CallCapability(context.Context, *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	r.write()
	return nil, nil
}

func TestPanicSafeExecutionHelper_PassesThroughResults(t *testing.T) {
	t.Parallel()

	inner := &passthroughHelper{}
	helper := newPanicSafeExecutionHelper(inner, logger.Test(t))

	resp, err := helper.CallCapability(context.Background(), &sdkpb.CapabilityRequest{Id: "cap"})
	require.NoError(t, err)
	require.NotNil(t, resp)

	secrets, err := helper.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{})
	require.NoError(t, err)
	require.Len(t, secrets, 1)

	donTime, err := helper.GetDONTime()
	require.NoError(t, err)
	assert.Equal(t, time.Unix(7, 0), donTime)

	assert.Equal(t, "exec-1", helper.GetWorkflowExecutionID())
	assert.Equal(t, time.Unix(42, 0), helper.GetNodeTime())
	require.NoError(t, helper.EmitUserLog("hello"))
	require.NoError(t, helper.EmitUserMetric(context.Background(), &wfpb.WorkflowUserMetric{}))
}

func TestPanicSafeExecutionHelper_PassesThroughErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("inner failure")
	helper := newPanicSafeExecutionHelper(&passthroughHelper{err: sentinel}, logger.Test(t))

	for name, call := range guardedCalls(helper) {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(), sentinel)
		})
	}
}
