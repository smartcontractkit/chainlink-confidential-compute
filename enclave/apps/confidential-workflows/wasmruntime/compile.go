package wasmruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/wasm/host"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/wasmlimits"
)

type PreparedArtifact struct {
	Path     string
	Deadline time.Time
}

// Compiler serializes all preparation, including decompression, file writing and
// native cleanup. Wasmtime's compilation cache remains enabled; handoff files are
// private to each execution.
type Compiler struct {
	dir  string
	slot chan struct{}
	// Guarded by slot. Cleanup retries must never target a later artifact.
	sequence uint64
}

// baseDir must support executable file mappings. An empty value uses os.TempDir.
func NewCompiler(baseDir string) (*Compiler, error) {
	dir, err := os.MkdirTemp(baseDir, "workflow-artifacts-")
	if err != nil {
		return nil, err
	}
	return &Compiler{
		dir: dir, slot: make(chan struct{}, 1),
	}, nil
}

// Close requires all Compile calls and workers to have finished.
func (c *Compiler) Close() error {
	return os.RemoveAll(c.dir)
}

func (c *Compiler) Compile(ctx context.Context, lggr logger.Logger, resolved wasmlimits.Config, binary []byte, timeout time.Duration) (PreparedArtifact, error) {
	queued := time.Now()
	select {
	case c.slot <- struct{}{}:
		defer func() { <-c.slot }()
	case <-ctx.Done():
		return PreparedArtifact{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return PreparedArtifact{}, err
	}
	started := time.Now()
	var deadline time.Time
	if timeout > 0 {
		deadline = started.Add(timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	path, err := c.compileToFile(ctx, lggr, resolved, binary)
	lggr.Infow("workflow compilation completed", "queueDuration", started.Sub(queued), "duration", time.Since(started), "error", err)
	// Native compilation is not interruptible. Observe expiry only after the
	// native module and limiters have been closed, before releasing the slot.
	if ctx.Err() != nil {
		RemoveArtifact(lggr, path)
		return PreparedArtifact{}, ctx.Err()
	}
	if err != nil {
		return PreparedArtifact{}, err
	}
	return PreparedArtifact{Path: path, Deadline: deadline}, nil
}

func (c *Compiler) compileToFile(ctx context.Context, lggr logger.Logger, resolved wasmlimits.Config, binary []byte) (path string, err error) {
	cfg := newModuleConfig(resolved)
	defer closeLimiters(lggr, cfg)
	cfg.Logger = lggr
	mod, err := host.NewModule(ctx, cfg, binary)
	if err != nil {
		return "", fmt.Errorf("creating wasm module: %w", err)
	}
	defer mod.Close()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	serialized, err := mod.Serialize()
	if err != nil {
		return "", fmt.Errorf("serializing wasm module: %w", err)
	}
	c.sequence++
	f, err := os.CreateTemp(c.dir, fmt.Sprintf("module-%d-", c.sequence))
	if err != nil {
		return "", fmt.Errorf("creating compiled artifact: %w", err)
	}
	path = f.Name()
	defer func() {
		if err != nil {
			RemoveArtifact(lggr, path)
		}
	}()
	_, writeErr := f.Write(serialized)
	closeErr := f.Close()
	if writeErr != nil {
		return path, fmt.Errorf("writing compiled artifact: %w", writeErr)
	}
	if closeErr != nil {
		return path, fmt.Errorf("closing compiled artifact: %w", closeErr)
	}
	return path, nil
}

// RemoveArtifact is best effort: deletion must not replace an execution result.
func RemoveArtifact(lggr logger.Logger, path string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		lggr.Warnw("cannot remove compiled workflow artifact", "path", path, "error", err)
	}
}
