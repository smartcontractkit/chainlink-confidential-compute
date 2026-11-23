//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// prepare readies the enclave for a post-mortem before the app starts: a
// memory-backed crash directory, core dumps, and a kernel that logs what it
// does to a dying process. Every step is best-effort and recorded.
func prepare(cfg config, n *notes) {
	if err := os.MkdirAll(cfg.crashDir, 0o700); err != nil {
		n.addf("cannot create %s: %v", cfg.crashDir, err)
	}
	if !cfg.systemSetup {
		n.addf("kernel crash settings skipped: %s is not set", EnvSystemSetup)
		return
	}
	// tmpfs rather than the root ramfs: a sparse core costs only the pages it
	// holds, and reading its holes back allocates nothing.
	if err := unix.Mount("tmpfs", cfg.crashDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=80%,mode=0700"); err != nil {
		n.addf("tmpfs mount on %s failed, using the root filesystem: %v", cfg.crashDir, err)
	} else {
		n.addf("mounted tmpfs on %s", cfg.crashDir)
	}

	for _, sysctl := range [][2]string{
		// A file pattern resolves in the crashing process's root, so this lands
		// in the crash directory whatever the enclave init did with chroot.
		{"kernel/core_pattern", filepath.Join(cfg.crashDir, "core.%e.%p.sig%s.%t")},
		{"kernel/core_uses_pid", "0"},
		{"fs/suid_dumpable", "1"},
		// Registers and code bytes for any signal that kills a process.
		{"kernel/print-fatal-signals", "1"},
		// Every kernel message to the console.
		{"kernel/printk", "8 4 1 7"},
		{"kernel/dmesg_restrict", "0"},
		// Per-task memory table when the OOM killer runs.
		{"vm/oom_dump_tasks", "1"},
		// Kill the offender and keep the VM up, so the kill can be reported.
		{"vm/panic_on_oom", "0"},
		{"vm/oom_kill_allocating_task", "0"},
	} {
		path := filepath.Join("/proc/sys", sysctl[0])
		if err := os.WriteFile(path, []byte(sysctl[1]), 0o644); err != nil {
			n.addf("sysctl %s=%q failed: %v", sysctl[0], sysctl[1], err)
			continue
		}
		got, _ := os.ReadFile(path)
		n.addf("sysctl %s=%q", sysctl[0], strings.TrimSpace(string(got)))
	}

	// Inherited by the app: lets the kernel write a core of any size.
	unlimited := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unlimited); err != nil {
		n.addf("setrlimit RLIMIT_CORE failed: %v", err)
	} else {
		n.addf("RLIMIT_CORE unlimited")
	}

	for _, path := range []string{"/proc/version", "/proc/cmdline"} {
		if data, err := os.ReadFile(path); err == nil {
			n.addf("%s: %s", path, strings.TrimSpace(string(data)))
		}
	}
}
