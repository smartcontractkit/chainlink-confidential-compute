package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Both enclaves of a suite run their host servers out of one app directory, and
// on Nitro they run the identical binary, so a check keyed on the path alone
// matches a sibling that is still serving by design. TestConfidentialHTTPE2E
// stops its first enclave mid-test and then asserts the second still answers,
// so that mismatch fails the suite rather than catching a real leak.
func TestRequireHostServerStoppedIgnoresSiblingEnclave(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skip("pgrep unavailable")
	}
	rootDir := t.TempDir()
	appDir := filepath.Join(rootDir, "enclave", "apps", "probe")
	require.NoError(t, os.MkdirAll(appDir, 0o750))

	// A stand-in whose command line has the same shape as a real host server.
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

	// CID 16 was never started, so its check must return at once even though the
	// sibling for CID 17 is alive in the same directory. Matching the sibling
	// would instead burn the whole hostServerExitBudget.
	//
	// Called synchronously on purpose: racing it against a select and failing the
	// test first would leave the helper polling against a finished *testing.T,
	// and its t.Errorf would then panic the whole package rather than report one
	// clean failure -- on exactly the regression this test exists to catch.
	started := time.Now()
	requireHostServerStopped(t, rootDir, "probe", "16")
	require.Less(t, time.Since(started), 10*time.Second,
		"requireHostServerStopped matched a sibling enclave's host server")
}
