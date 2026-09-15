package app

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
)

// panicSafeExecutionHelper converts a panic raised anywhere in the ExecutionHelper
// chain into an error return, so a bug in a capability call fails the execution
// instead of the enclave.
//
// The WASM host dispatches CallCapability and GetSecrets on goroutines it spawns
// itself (chainlink-common pkg/workflows/wasm/host/execution.go). A panic on one
// of those is invisible to both net/http's per-connection recover and the host's
// own recover in callStart, so it reaches the runtime and kills the process. The
// enclave app is PID 1 in the Nitro VM, so that terminates the enclave and
// restarts the pod. Returning an error instead lets the host turn it into a
// CapabilityResponse_Error, and the workflow sees a failed call.
//
// This type deliberately does not embed host.ExecutionHelper: every method is
// declared explicitly so a newly added interface method fails to compile here
// rather than silently passing through unguarded.
type panicSafeExecutionHelper struct {
	host.ExecutionHelper
	lggr logger.Logger
}

var _ host.ExecutionHelper = (*panicSafeExecutionHelper)(nil)

// newPanicSafeExecutionHelper wraps inner so panics surface as errors. Apply it
// outermost so it also covers the restriction-enforcing decorator.
func newPanicSafeExecutionHelper(inner host.ExecutionHelper, lggr logger.Logger) *panicSafeExecutionHelper {
	return &panicSafeExecutionHelper{ExecutionHelper: inner, lggr: lggr}
}

// recoverTo turns a panic into err, logging the value and stack. Call it as
// `defer h.recoverTo("Method", &err)` from a method with a named error return;
// the other named results keep their zero values.
func (h *panicSafeExecutionHelper) recoverTo(method string, err *error) {
	r := recover()
	if r == nil {
		return
	}
	if h.lggr != nil {
		h.lggr.Errorw("recovered panic in execution helper",
			"method", method,
			"panic", r,
			"stack", string(debug.Stack()),
		)
	}
	*err = fmt.Errorf("panic in %s: %v", method, r)
}

func (h *panicSafeExecutionHelper) CallCapability(ctx context.Context, req *sdkpb.CapabilityRequest) (resp *sdkpb.CapabilityResponse, err error) {
	defer h.recoverTo("CallCapability", &err)
	return h.ExecutionHelper.CallCapability(ctx, req)
}

func (h *panicSafeExecutionHelper) GetSecrets(ctx context.Context, req *sdkpb.GetSecretsRequest) (resp []*sdkpb.SecretResponse, err error) {
	defer h.recoverTo("GetSecrets", &err)
	return h.ExecutionHelper.GetSecrets(ctx, req)
}
