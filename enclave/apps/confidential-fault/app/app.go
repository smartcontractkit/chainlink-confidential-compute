// Package app implements confidential-fault, a test-only enclave app that fails
// in a requested way.
//
// It exists so the enclave supervisor and the host's crash-reporting path can be
// exercised against a real Nitro enclave. Nothing outside the VM can signal the
// enclave application, and terminating the enclave destroys the VM before the
// supervisor runs, so the only way to reach those paths end to end is for the
// application itself to fail on request.
//
// Keeping that in a separate app rather than behind a flag in a production one
// means no production image gains the capability at all: this app's EIF is only
// ever built by tests.
package app

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// Fault names accepted as the public input of an /execute request.
const (
	// FaultNone returns normally; the control case.
	FaultNone = "none"

	// FaultExit calls os.Exit, the shape of a deliberate abort such as a
	// startup guard or a logger.Fatalf. Reported as "exit status N".
	FaultExit = "exit"

	// FaultKill sends itself SIGKILL, the shape of an OOM kill. Uncatchable, so
	// it is reported as a signal rather than an exit code.
	FaultKill = "kill"

	// FaultRuntimeSignal sends itself SIGSEGV. The Go runtime intercepts it,
	// prints "unexpected signal during runtime execution" and exits 2, which is
	// how a genuine SIGSEGV inside cgo (e.g. wasmtime) presents.
	FaultRuntimeSignal = "runtime-signal"

	// FaultGoroutinePanic panics on a goroutine of its own. Neither net/http's
	// per-connection recover nor any handler-scoped recover can see it, so the
	// runtime terminates the process. This is the containment gap the
	// ExecutionHelper guards exist to close.
	FaultGoroutinePanic = "goroutine-panic"

	// FaultHandlerPanic panics on the request goroutine. net/http recovers it,
	// so the enclave must survive; the control case for the one above.
	FaultHandlerPanic = "handler-panic"
)

// faultDelay gives the enclave time to write the /execute response before it
// dies, so a test sees the fault it asked for rather than a connection reset it
// cannot attribute.
const faultDelay = 250 * time.Millisecond

type faultEnclaveApp struct{}

var _ types.EnclaveApp = (*faultEnclaveApp)(nil)

// NewFaultEnclaveApp returns the test-only fault-injecting EnclaveApp.
func NewFaultEnclaveApp() types.EnclaveApp {
	return &faultEnclaveApp{}
}

// Execute injects the fault named by inputData. Faults that kill the process are
// scheduled on a timer so the response is delivered first; faults that do not
// take effect immediately return a description of what was requested.
func (a *faultEnclaveApp) Execute(_ [32]byte, appID string, inputData []byte, _ map[string][]byte, emitter types.Emitter, _ ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
	if appID != types.AppIDConfidentialFault {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("invalid app ID: expected %s, got %s", types.AppIDConfidentialFault, appID),
			Code:  http.StatusBadRequest,
		}
	}

	fault := strings.TrimSpace(string(inputData))
	if fault == "" {
		fault = FaultNone
	}
	emitter.Emit("fault_requested", map[string]any{"fault": fault})

	switch fault {
	case FaultNone:
		return []byte(FaultNone), nil

	case FaultHandlerPanic:
		// Recovered by net/http's per-connection handler; the enclave lives and
		// the caller sees a truncated response.
		panic("confidential-fault: handler panic")

	case FaultExit:
		afterResponse(func() { os.Exit(9) })

	case FaultKill:
		afterResponse(func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) })

	case FaultRuntimeSignal:
		afterResponse(func() { _ = syscall.Kill(os.Getpid(), syscall.SIGSEGV) })

	case FaultGoroutinePanic:
		afterResponse(func() { panic("confidential-fault: panic on a spawned goroutine") })

	default:
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("unknown fault %q", fault),
			Code:  http.StatusBadRequest,
		}
	}

	return []byte(fault + " scheduled"), nil
}

// afterResponse runs fn on its own goroutine once the response has had time to
// reach the host. Deliberately unrecovered: the point is for the failure to
// reach the runtime.
func afterResponse(fn func()) {
	go func() {
		time.Sleep(faultDelay)
		// Give the scheduler a chance to flush the response write before the
		// process stops existing.
		runtime.Gosched()
		fn()
	}()
}
