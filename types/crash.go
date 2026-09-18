package types

// CrashReport is the post-mortem the enclave supervisor sends to the host when
// the enclave application exits.
//
// It deliberately carries no stderr. The host sits outside the enclave's trust
// boundary, and a Go traceback prints raw argument words that can hold pointers
// into, or fragments of, key material and plaintext. Only the exit status
// crosses the boundary; the traceback itself stays on the enclave console, where
// it is reachable in a --debug-mode enclave for reproduction.
//
// The status alone separates the failure classes that matter: an OOM kill
// (SIGKILL), a Go runtime fatal error or unrecovered panic (exit 2), a startup
// guard rejecting the environment (exit 1), and a clean exit. Memory figures are
// deliberately absent: the host already polls the enclave's /memory endpoint and
// records total, available, RSS and peak RSS as metrics, so repeating them here
// would duplicate data the host can already query.
// CrashReportAck is what the host writes back once it has logged a CrashReport.
// The supervisor blocks on it before exiting: a successful write on its side
// proves only that the bytes reached the local socket buffer, and the enclave VM
// is destroyed moments later, which can discard anything the host has not read.
const CrashReportAck = "ack\n"

type CrashReport struct {
	// App is the executable name, to disambiguate which enclave app died.
	App string `json:"app"`
	// ExitCode is the child's exit status, or 128+signal when it was signalled.
	ExitCode int `json:"exit_code"`
	// Status is os.ProcessState's own rendering of the wait status, e.g.
	// "exit status 2", "signal: killed", "signal: segmentation fault (core
	// dumped)". It is the authoritative reading: it also covers the core-dump
	// and stop/continue cases that ExitCode and Signal alone cannot express.
	Status string `json:"status,omitempty"`
	// Signal is set when the child was terminated by a signal (e.g. "killed").
	Signal string `json:"signal,omitempty"`
	// Error is set when the child could not be waited on at all.
	Error string `json:"error,omitempty"`
}
