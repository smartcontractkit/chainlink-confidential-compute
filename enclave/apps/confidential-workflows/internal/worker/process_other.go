//go:build !linux

package worker

import "syscall"

// Parent-death signaling is Linux-only and unavailable to non-Linux fake runs.
func workerProcessAttrs() *syscall.SysProcAttr { return nil }
