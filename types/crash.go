package types

// CrashReport is the post-mortem the enclave supervisor sends to the host when
// the enclave application exits.
//
// The enclave application is PID 1 in the Nitro VM, so its stderr goes to the
// enclave console, which is unreadable unless the enclave was launched with
// --debug-mode (which zeroes the PCRs). This carries that output out over vsock
// instead, so panics, runtime fatal errors and cgo signal reports survive the
// teardown.
type CrashReport struct {
	// App is the executable name, to disambiguate which enclave app died.
	App string `json:"app"`
	// ExitCode is the child's exit status, or 128+signal when it was signalled.
	ExitCode int `json:"exit_code"`
	// Signal is set when the child was terminated by a signal (e.g. "segmentation fault").
	Signal string `json:"signal,omitempty"`
	// Error is set when the child could not be waited on at all.
	Error string `json:"error,omitempty"`
	// StderrTail is the retained tail of the child's stderr.
	StderrTail string `json:"stderr_tail"`
	// Truncated reports whether output was dropped from the front of StderrTail.
	Truncated bool `json:"truncated"`
}
