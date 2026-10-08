// Package workerexec is imported only by worker binaries, never coordinators.
package workerexec

import (
	"encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"google.golang.org/protobuf/proto"
)

type failedKey struct{ err error }

func (k failedKey) GetKeyPairForRequest([32]byte) (keychain.Keypair, error) { return nil, k.err }

func Execute(job worker.Job, lggr logger.Logger, att attestor.Attestor, fetcher *httpfetch.Fetcher) worker.Reply {
	var reply worker.Reply
	fail := func(message string, err error) worker.Reply {
		lggr.Errorw(message, "error", err)
		reply.Error = &types.ExecuteError{Error: message, Code: 500}
		return reply
	}
	var execution confworkflowtypes.WorkflowExecution
	if err := proto.Unmarshal(job.Execution, &execution); err != nil {
		return fail("invalid worker execution job", err)
	}
	var dispatcher app.RemoteDispatcher
	if job.Gateway.URL != "" {
		var keys app.RequestKeyProvider
		if job.KeyError != "" {
			keys = failedKey{errors.New(job.KeyError)}
		} else if job.Key != nil {
			kc, err := keychain.NewRequestKeychain(job.RequestID, *job.Key)
			if err != nil {
				return fail("invalid worker key provisioning", err)
			}
			keys = kc
		} else {
			return fail("missing worker key provisioning", nil)
		}
		var err error
		dispatcher, err = nitrotransport.Dispatcher(app.GatewayConfig(job.Gateway), job.Config, att, keys, lggr, binary.BigEndian.Uint64(job.RequestID[:8]))
		if err != nil {
			return fail("cannot construct worker dispatcher", err)
		}
	}
	events := server.NewResponseEmitter()
	reply.Result, reply.Error = app.ExecuteWorkflow(wasmruntime.Execute, lggr, job.Limits, job.RequestID, &execution, job.Binary,
		job.SignedRequests, events, dispatcher, fetcher, job.ExecutionTimeout)
	reply.Events = events.GetMetricEvents()
	return reply
}

func Serve(in io.Reader, out io.Writer, lggr logger.Logger, openAttestor func() (attestor.Attestor, func(), error)) error {
	var job worker.Job
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("reading worker input: %w", err)
	}
	if err := json.Unmarshal(data, &job); err != nil {
		return fmt.Errorf("invalid worker input: %w", err)
	}
	var att attestor.Attestor
	if job.Gateway.URL != "" {
		var cleanup func()
		var err error
		att, cleanup, err = openAttestor()
		if err != nil {
			lggr.Errorw("cannot open worker attestor", "error", err)
			return json.NewEncoder(out).Encode(worker.Reply{Error: &types.ExecuteError{Error: "cannot open worker attestor", Code: 500}})
		}
		defer cleanup()
	}
	reply := Execute(job, lggr, att, nitrotransport.HTTPFetcher(job.HTTPTimeout))
	return json.NewEncoder(out).Encode(reply)
}

func Main(openAttestor func() (attestor.Attestor, func(), error)) int {
	lggr, err := logger.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot construct worker logger: %v\n", err)
		return 1
	}
	defer func() { _ = lggr.Sync() }()
	if err := Serve(os.Stdin, os.Stdout, lggr, openAttestor); err != nil {
		lggr.Errorw("worker protocol failed", "error", err)
		return 1
	}
	return 0
}
