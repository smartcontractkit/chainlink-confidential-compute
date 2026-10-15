package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultNitroCLIBinary      = "nitro-cli"
	maxNitroCLIOutputBytes     = 64 * 1024
	maxNitroCLIDiagnosticBytes = 2 * 1024
	nitroCLIWaitDelay          = time.Second
)

type nitroRunConfig struct {
	CPUCount    uint32
	MemoryMiB   uint64
	EnclaveCID  uint32
	EnclaveName string
	EIFPath     string
	DebugMode   bool
}

type nitroRunResult struct {
	EnclaveID  string `json:"EnclaveID"`
	EnclaveCID uint32 `json:"EnclaveCID"`
}

type nitroEnclaveDescription struct {
	EnclaveName string `json:"EnclaveName"`
	EnclaveID   string `json:"EnclaveID"`
	EnclaveCID  uint32 `json:"EnclaveCID"`
	State       string `json:"State"`
}

type nitroCLI interface {
	Run(context.Context, nitroRunConfig) (nitroRunResult, error)
	Describe(context.Context) ([]nitroEnclaveDescription, error)
	Terminate(context.Context, string) error
}

type commandResult struct {
	stdout          []byte
	stderr          []byte
	stdoutTruncated bool
	stderrTruncated bool
}

type commandRunner interface {
	Run(context.Context, string, ...string) (commandResult, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) (commandResult, error) {
	stdout := newBoundedBuffer(maxNitroCLIOutputBytes)
	stderr := newBoundedBuffer(maxNitroCLIOutputBytes)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = nitroCLIWaitDelay
	err := cmd.Run()
	return commandResult{
		stdout:          stdout.Bytes(),
		stderr:          stderr.Bytes(),
		stdoutTruncated: stdout.Truncated(),
		stderrTruncated: stderr.Truncated(),
	}, err
}

type execNitroCLI struct {
	binary string
	runner commandRunner
}

var _ nitroCLI = (*execNitroCLI)(nil)

func newNitroCLI() *execNitroCLI {
	return newNitroCLIWithRunner(defaultNitroCLIBinary, execCommandRunner{})
}

func newNitroCLIWithRunner(binary string, runner commandRunner) *execNitroCLI {
	return &execNitroCLI{binary: binary, runner: runner}
}

func (c *execNitroCLI) Run(ctx context.Context, config nitroRunConfig) (nitroRunResult, error) {
	config.EIFPath = strings.TrimSpace(config.EIFPath)
	if err := config.validate(); err != nil {
		return nitroRunResult{}, err
	}

	args := []string{
		"--cpu-count", strconv.FormatUint(uint64(config.CPUCount), 10),
		"--memory", strconv.FormatUint(config.MemoryMiB, 10),
	}
	if config.EnclaveCID != 0 {
		args = append(args, "--enclave-cid", strconv.FormatUint(uint64(config.EnclaveCID), 10))
	}
	if config.EnclaveName != "" {
		args = append(args, "--enclave-name", config.EnclaveName)
	}
	if config.DebugMode {
		args = append(args, "--debug-mode")
	}
	args = append(args, "--eif-path", config.EIFPath)

	output, err := c.execute(ctx, "run-enclave", args...)
	if err != nil {
		return nitroRunResult{}, err
	}

	var result nitroRunResult
	if err := decodeSingleJSON(output, &result); err != nil {
		return nitroRunResult{}, fmt.Errorf("decode run-enclave output: %w", err)
	}
	if result.EnclaveID == "" {
		return nitroRunResult{}, errors.New("run-enclave output missing EnclaveID")
	}
	if result.EnclaveCID == 0 {
		return nitroRunResult{}, errors.New("run-enclave output missing EnclaveCID")
	}

	return result, nil
}

func (c *execNitroCLI) Describe(ctx context.Context) ([]nitroEnclaveDescription, error) {
	output, err := c.execute(ctx, "describe-enclaves")
	if err != nil {
		return nil, err
	}

	var descriptions []nitroEnclaveDescription
	if err := decodeSingleJSON(output, &descriptions); err != nil {
		return nil, fmt.Errorf("decode describe-enclaves output: %w", err)
	}
	if descriptions == nil {
		return nil, errors.New("describe-enclaves output must be a JSON array")
	}
	for i, description := range descriptions {
		if description.EnclaveID == "" {
			return nil, fmt.Errorf("describe-enclaves entry %d missing EnclaveID", i)
		}
		if description.State == "" {
			return nil, fmt.Errorf("describe-enclaves entry %d missing State", i)
		}
	}

	return descriptions, nil
}

func (c *execNitroCLI) Terminate(ctx context.Context, enclaveID string) error {
	enclaveID = strings.TrimSpace(enclaveID)
	if enclaveID == "" {
		return errors.New("enclave ID must not be empty")
	}
	_, err := c.execute(ctx, "terminate-enclave", "--enclave-id", enclaveID)
	return err
}

func (c *execNitroCLI) execute(ctx context.Context, subcommand string, args ...string) ([]byte, error) {
	result, err := c.runner.Run(ctx, c.binary, append([]string{subcommand}, args...)...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = errors.Join(err, ctxErr)
		}
		if stderr := formatCommandOutput(result.stderr, result.stderrTruncated); stderr != "" {
			return nil, fmt.Errorf("%s %s failed: %w: %s", c.binary, subcommand, err, stderr)
		}
		return nil, fmt.Errorf("%s %s failed: %w", c.binary, subcommand, err)
	}
	if result.stdoutTruncated {
		return nil, fmt.Errorf("%s %s output exceeded %d bytes", c.binary, subcommand, maxNitroCLIOutputBytes)
	}
	return result.stdout, nil
}

func (config nitroRunConfig) validate() error {
	if config.CPUCount == 0 {
		return errors.New("CPU count must be greater than zero")
	}
	if config.MemoryMiB == 0 {
		return errors.New("memory must be greater than zero")
	}
	if strings.TrimSpace(config.EIFPath) == "" {
		return errors.New("EIF path must not be empty")
	}
	return nil
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON value")
		}
		return err
	}
	return nil
}

func formatCommandOutput(output []byte, truncated bool) string {
	if len(output) > maxNitroCLIDiagnosticBytes {
		output = output[:maxNitroCLIDiagnosticBytes]
		truncated = true
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		return ""
	}
	message = strconv.Quote(message)
	if truncated {
		message += "...truncated"
	}
	return message
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:min(len(data), remaining)])
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return written, nil
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *boundedBuffer) Truncated() bool {
	return b.truncated
}
