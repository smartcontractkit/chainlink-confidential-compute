//go:build !linux

package worker

import "syscall"

// Parent-death signaling is Linux-only; other platforms support local fake runs.
func workerProcessAttrs() *syscall.SysProcAttr { return nil }
