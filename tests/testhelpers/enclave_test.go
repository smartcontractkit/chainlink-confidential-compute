package testhelpers

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRequireHostServerStoppedIgnoresSiblingEnclave(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skip("pgrep unavailable")
	}
	rootDir := t.TempDir()
	appDir := filepath.Join(rootDir, "enclave", "apps", "probe")
	require.NoError(t, os.MkdirAll(appDir, 0o750))

	// Use the production path shape exercised by the process matcher.
	binary := filepath.Join(appDir, "host-server-cid17")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nwhile :; do sleep 1; done\n"), 0o500))
	sibling := exec.Command(binary, "--port=1", "--config-port=2", "--enclave-cid=17", "--enclave-port=5000")
	require.NoError(t, sibling.Start())
	t.Cleanup(func() {
		_ = sibling.Process.Kill()
		_, _ = sibling.Process.Wait()
	})
	require.Eventually(t, func() bool {
		pids, ok := hostServerPIDs(t, rootDir, "probe", "17")
		return ok && len(pids) == 1
	}, 5*time.Second, 50*time.Millisecond, "stand-in host server never appeared")

	started := time.Now()
	requireHostServerStopped(t, rootDir, "probe", "16")
	require.Less(t, time.Since(started), 10*time.Second,
		"requireHostServerStopped matched a sibling enclave's host server")
}
