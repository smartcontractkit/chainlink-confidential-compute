//go:build linux

package memlimit

import "golang.org/x/sys/unix"

// totalMemoryMB reports the enclave VM's total RAM in MiB via sysinfo(2).
// Inside a Nitro enclave this is the guest kernel's MemTotal, which runs a bit
// below the nitro-cli --memory request (kernel/hugepage reservation), so it is
// an honest measure of usable RAM.
func totalMemoryMB() (uint64, error) {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 0, err
	}
	return (uint64(si.Totalram) * uint64(si.Unit)) / (1024 * 1024), nil
}
