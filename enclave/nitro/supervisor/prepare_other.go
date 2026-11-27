//go:build !linux

package main

import "os"

// prepare only creates the crash directory off Linux, where the supervisor
// runs for tests and the fake enclave.
func prepare(cfg config, n *notes) {
	if err := os.MkdirAll(cfg.crashDir, 0o700); err != nil {
		n.addf("cannot create %s: %v", cfg.crashDir, err)
	}
	n.addf("kernel crash settings skipped: not Linux")
}
