// Package workerexec is imported only by worker binaries, never coordinators.
package workerexec

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/nitrotransport"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/wasmruntime"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"google.golang.org/protobuf/proto"
)

type failedKey struct{ err error }

func (k failedKey) GetKeyPairForRequest([32]byte) (keychain.Keypair, error) { return nil, k.err }

func Execute(job worker.Job, lggr logger.Logger, att attestor.Attestor, fetcher *httpfetch.Fetcher) worker.Reply {
	reply := worker.Reply{Version: worker.Version, RequestID: job.RequestID}
	fail := func(message string) worker.Reply {
		reply.Outcome = worker.SetupError
		reply.Error = &types.ExecuteError{Error: message, Code: 500}
		return reply
	}
	var execution confworkflowtypes.WorkflowExecution
	if job.Version != worker.Version || proto.Unmarshal(job.Execution, &execution) != nil || execution.WorkflowId == "" || execution.SdkExecuteRequest == nil {
		return fail("invalid worker execution job")
	}
	hash := sha256.Sum256(job.Binary)
	if !bytes.Equal(hash[:], execution.BinaryHash) {
		return fail("worker artifact hash mismatch")
	}
	var dispatcher app.RemoteDispatcher
	if job.Gateway.URL != "" {
		if att == nil {
			return fail("worker attestor is unavailable")
		}
		var keys app.RequestKeyProvider
		if job.KeyError != "" {
			keys = failedKey{errors.New(job.KeyError)}
		} else if job.Key != nil {
			kc, err := keychain.NewRequestKeychain(job.RequestID, *job.Key)
			if err != nil {
				return fail("invalid worker key provisioning")
			}
			keys = kc
		} else {
			return fail("missing worker key provisioning")
		}
		var err error
		dispatcher, err = nitrotransport.Dispatcher(app.GatewayConfig{
			URL: job.Gateway.URL, RequestTimeout: job.Gateway.RequestTimeout,
			RetryBackoff: job.Gateway.RetryBackoff, RetryTimeout: job.Gateway.RetryTimeout,
		}, job.Config, att, keys, lggr)
		if err != nil {
			return fail("cannot construct worker dispatcher")
		}
	}
	var events worker.Events
	result, execErr := app.ExecuteWorkflow(wasmruntime.Execute, lggr, job.Limits, job.RequestID, &execution, job.Binary,
		job.SignedRequests, &events, dispatcher, fetcher, job.ExecutionTimeout)
	var err error
	reply.Events, err = events.Snapshot()
	if err != nil {
		return fail(err.Error())
	}
	if execErr != nil {
		reply.Outcome, reply.Error = worker.ExecutionError, execErr
		return reply
	}
	// The outer response's base64 output must fit the existing client envelope.
	if result == nil || proto.Size(result) > types.MaxEnclaveResponseBodyBytes {
		return fail("worker result exceeds maximum allowed size")
	}
	reply.Result, err = proto.Marshal(result)
	if err != nil {
		return fail("cannot encode worker result")
	}
	reply.Outcome = worker.Success
	return reply
}

func Serve(in io.Reader, out io.Writer, length int64, lggr logger.Logger, openAttestor func() (attestor.Attestor, func(), error)) error {
	var job worker.Job
	if err := worker.Decode(in, length, &job, nil); err != nil {
		return errors.New("invalid worker input")
	}
	var att attestor.Attestor
	if job.Gateway.URL != "" {
		var cleanup func()
		var err error
		att, cleanup, err = openAttestor()
		if err != nil {
			return worker.WriteReply(out, worker.Reply{Version: worker.Version, RequestID: job.RequestID,
				Outcome: worker.SetupError, Error: &types.ExecuteError{Error: "cannot open worker attestor", Code: 500}})
		}
		defer cleanup()
	}
	reply := Execute(job, lggr, att, nitrotransport.HTTPFetcher(job.HTTPTimeout))
	return worker.WriteReply(out, reply)
}

func Main(openAttestor func() (attestor.Attestor, func(), error)) int {
	length := flag.Int64("job-bytes", 0, "Exact maximum job size on stdin")
	parent := flag.Int("parent-pid", 0, "Expected coordinator PID")
	flag.Parse()
	if *parent <= 0 || os.Getppid() != *parent || *length <= 0 || flag.NArg() != 0 {
		return 1
	}
	lggr := logger.NewWithSync(os.Stderr)
	defer lggr.Sync()
	if err := Serve(os.Stdin, os.Stdout, *length, lggr, openAttestor); err != nil {
		fmt.Fprintln(os.Stderr, "worker protocol failed")
		return 1
	}
	return 0
}
