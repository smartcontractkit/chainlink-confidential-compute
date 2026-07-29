//go:build !linux

package memlimit

import "errors"

// totalMemoryMB is unsupported off Linux; MaxConcurrentExecutions then uses
// FallbackConcurrency. The enclave only ever runs on Linux; this exists so the
// package (and its test) builds on dev machines.
func totalMemoryMB() (uint64, error) {
	return 0, errors.New("total memory introspection is only supported on linux")
}
