// Command enclave-supervisor runs the enclave application as a child process,
// watches it from the outside, and ships everything it can learn about its
// death to the host over vsock.
//
// DEBUG BUILDS ONLY. Nothing here is redacted: tracebacks, the kernel log,
// per-execution trace records and core dumps all leave the enclave. It exists
// to find out why the confidential-workflows enclave dies and must never be
// part of a production image.
//
// The enclave init (PID 1) forks the image entrypoint, waits on that pid and
// then reboots, so the VM lives exactly as long as this process. Sitting in the
// entrypoint slot lets the supervisor outlive the app, collect, and hold the VM
// open until the host has the report and the console has drained.
//
// While the app runs, a live stream carries the kernel log, the app's trace
// records, periodic /proc samples and any fatal runtime output as it is being
// written. When the app exits, a report archive follows with the full set.
//
// Usage:
//
//	enclave-supervisor /usr/bin/enclave-app [app args...]
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <enclave-app> [args...]\n", os.Args[0])
		os.Exit(2)
	}
	// The supervisor shares the enclave's vCPUs and memory with the app; keep
	// it small. It is exempt from the OOM killer, so it must not be the one
	// that uses the memory up.
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(256 << 20)
	os.Exit(supervise(os.Args[1], os.Args[2:]))
}
