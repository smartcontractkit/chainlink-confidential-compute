// Command enclave-supervisor runs the enclave application as a child process and
// reports its exit status to the host over vsock when it dies.
//
// Why this exists: AWS's enclave init (aws-nitro-enclaves-sdk-bootstrap) is
// PID 1. It forks the image entrypoint, waits on that pid, computes the exit
// status, and then calls reboot() — so the status dies with the VM. Nothing on
// the host can recover it afterwards. nitro-cli describe-enclaves reports only
// running enclaves and their State, with no exit code or termination reason, and
// a terminated enclave disappears from the listing entirely; the sidecar polling
// it learns that the enclave is gone, never why. The console would have more,
// but it is unreadable unless the enclave was launched with --debug-mode, which
// zeroes the PCRs and breaks attestation.
//
// Interposing the supervisor in the entrypoint slot gives that status somewhere
// to go. It is the discriminator triage actually needs: exit 2 for a Go runtime
// fatal error or unrecovered panic, 137 for a SIGKILL such as an OOM kill,
// exit 1 for a startup guard rejecting the environment, against a clean exit.
//
// The application's stderr is passed through to the enclave console untouched
// and never captured — the host is outside the enclave's trust boundary. See
// types.CrashReport.
//
// Usage:
//
//	enclave-supervisor /usr/bin/enclave-app [app args...]
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <enclave-app> [args...]\n", os.Args[0])
		os.Exit(2)
	}
	os.Exit(supervise(os.Args[1], os.Args[2:]))
}
