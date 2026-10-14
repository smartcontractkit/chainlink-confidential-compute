package workerexec

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFakeCoordinatorLifecycle(t *testing.T) {
	workerPath := build(t, "../..", "./environments/fake-worker", "worker", "CGO_ENABLED=1")
	coordinator := build(t, "../..", "./environments/fake", "coordinator", "CGO_ENABLED=1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	// The fake VSOCK backend maps (CID, port) to CID*1000 + port%10000 + 10000.
	cid, vsockPort := (port-10000)/1000, port%1000
	cmd := exec.Command(coordinator, "--worker-path", workerPath, "--vsock-port", strconv.Itoa(vsockPort))
	cmd.Env = append(os.Environ(), "VSOCK_BACKEND=tcp", "ENCLAVE_CID="+strconv.Itoa(cid), "TMPDIR="+t.TempDir())
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var stopped bool
	t.Cleanup(func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	client := &http.Client{Timeout: time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/memory")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-done:
		stopped = true
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, syscall.SIGTERM, exit.Sys().(syscall.WaitStatus).Signal())
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not exit after SIGTERM")
	}
}
