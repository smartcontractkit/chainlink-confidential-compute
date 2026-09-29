package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
)

const exitGrace = 2 * time.Second

// Processes runs one fresh child per execution, without retries or a worker pool.
type Processes struct {
	path   string
	args   []string
	env    []string
	keys   keychain.Keychain
	logger logger.Logger
}

func NewProcesses(path string, args, environment []string, keys keychain.Keychain, lggr logger.Logger) (*Processes, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("worker path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("worker executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("worker is not executable")
	}
	return &Processes{path: path, args: args, env: environment, keys: keys, logger: lggr}, nil
}

func (p *Processes) Run(ctx context.Context, job Job) (Reply, error) {
	if job.Gateway.URL != "" {
		if p.keys == nil {
			job.KeyError = "worker keychain is unavailable"
		} else {
			var err error
			job.Key, err = keychain.SnapshotForRequest(p.keys, job.RequestID)
			if err != nil {
				job.KeyError = err.Error()
			}
		}
	}
	data, err := json.Marshal(job)
	if err != nil {
		return Reply{}, errors.New("encoding worker job")
	}

	// Linux ties Pdeathsig to the spawning thread. Keeping it alive prevents Go's
	// thread retirement from killing a worker before its execution finishes.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := replyBuffer{cancel: cancel}
	cmd := exec.CommandContext(ctx, p.path, p.args...)
	cmd.Env = append(os.Environ(), p.env...)
	cmd.SysProcAttr = workerProcessAttrs()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(data), &out, os.Stderr
	cmd.WaitDelay = exitGrace
	start := time.Now()
	err = cmd.Run()
	if out.timer != nil {
		out.timer.Stop()
	}
	if p.logger != nil && cmd.ProcessState != nil {
		var peakRSS int64
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			peakRSS = usage.Maxrss
			if runtime.GOOS == "darwin" {
				peakRSS /= 1024
			}
		}
		p.logger.Infow("worker completed", "requestID", fmt.Sprintf("%x", job.RequestID), "pid", cmd.Process.Pid,
			"elapsed", time.Since(start), "exit", cmd.ProcessState.String(), "error", err, "peakRSSKB", peakRSS)
	}
	if err != nil {
		return Reply{}, fmt.Errorf("worker: %w", err)
	}
	return DecodeReply(out.buf.Bytes())
}

// Stdout contains only the final reply, so its first byte starts the exit grace.
// The buffer is not embedded: io.Copy must not bypass Write via Buffer.ReadFrom.
type replyBuffer struct {
	buf    bytes.Buffer
	cancel context.CancelFunc
	timer  *time.Timer
}

func (b *replyBuffer) Write(p []byte) (int, error) {
	if b.timer == nil {
		b.timer = time.AfterFunc(exitGrace, b.cancel)
	}
	if len(p) > MaxReplyBytes-b.buf.Len() {
		b.cancel()
		return 0, errors.New("worker reply exceeds limit")
	}
	return b.buf.Write(p)
}
