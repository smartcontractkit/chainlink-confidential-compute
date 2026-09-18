package types

// CrashReportAck is what the host writes back once it has logged a CrashReport.
// The supervisor blocks on it before exiting: a successful write on its side
// proves only that the bytes reached the local socket buffer, and the enclave VM
// is destroyed moments later, which can discard anything the host has not read.
const CrashReportAck = "ack\n"

// CrashReport is the post-mortem the enclave supervisor sends to the host when
// the enclave application exits.
//
// It deliberately carries no stderr. The host sits outside the enclave's trust
// boundary, and a Go traceback prints raw argument words that can hold pointers
// into, or fragments of, key material and plaintext. Only the exit status
// crosses the boundary; the traceback itself stays on the enclave console, where
// it is reachable in a --debug-mode enclave for reproduction.
//
// The status narrows the failure class; it does not diagnose a cause, and should
// not be read as though it did. Died-by-signal, exited-with-a-code and exited
// cleanly are three genuinely different situations, and which one occurred is
// the first branch triage needs — but no further:
//
//   - A signal is not self-explaining. SIGKILL is what an enclave OOM kill looks
//     like, but the signal alone does not establish one; weigh it against
//     PeakRSSBytes and the enclave memory metrics the host polls from /memory.
//   - An exit code is a hint, not an attribution. The Go runtime exits 2 for an
//     unrecovered panic or a fatal error, but so does flag.Parse on a malformed
//     argument, and any dependency may call os.Exit with anything it likes.
//
// Only the peak memory figure is carried, not a live snapshot. The host already
// polls /memory for total, available, RSS and peak RSS, so repeating a current
// reading here would duplicate that. The peak is the exception: the /memory
// series can only show a high-water mark that some later poll observed, and an
// allocation burst fast enough to trigger the OOM killer is never followed by
// one, because the process is already gone.
type CrashReport struct {
	// App is the executable name, to disambiguate which enclave app died.
	App string `json:"app"`
	// ExitCode is the child's exit status, or 128+signal when it was signalled.
	ExitCode int `json:"exit_code"`
	// Status is os.ProcessState's own rendering of the wait status, e.g.
	// "exit status 2", "signal: killed", "signal: segmentation fault (core
	// dumped)". It is the complete reading of that status: it also covers the
	// core-dump and stop/continue cases ExitCode and Signal cannot express.
	Status string `json:"status,omitempty"`
	// Signal is set when the child was terminated by a signal (e.g. "killed").
	Signal string `json:"signal,omitempty"`
	// Error is set when the child could not be waited on at all.
	Error string `json:"error,omitempty"`
	// PeakRSSBytes is the application's high-water resident set (ru_maxrss),
	// recorded by the kernel at termination. Zero if it reported none.
	PeakRSSBytes uint64 `json:"peak_rss_bytes,omitempty"`
}
