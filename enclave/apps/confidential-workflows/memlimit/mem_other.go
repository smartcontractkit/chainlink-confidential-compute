//go:build !linux

package memlimit

import "errors"

// The Nitro guest is Linux; fake environments do not derive a memory budget.
func totalMemoryMB() (uint64, error) {
	return 0, errors.New("total memory introspection is only supported on linux")
}
