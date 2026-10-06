package workerexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/worker"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/keychain"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestSetupFailuresLogCause(t *testing.T) {
	for _, tc := range []struct {
		name    string
		job     worker.Job
		message string
	}{
		{"execution", worker.Job{Execution: []byte("bad protobuf")}, "invalid worker execution job"},
		{"key", worker.Job{Gateway: worker.GatewayConfig{URL: "https://gateway.example"}, Key: &keychain.BoxKeySnapshot{}}, "invalid worker key provisioning"},
		{"dispatcher", worker.Job{Gateway: worker.GatewayConfig{URL: "://"}, KeyError: "key unavailable"}, "cannot construct worker dispatcher"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
			reply := Execute(tc.job, lggr, nil, nil)
			require.NotNil(t, reply.Error)
			require.Equal(t, tc.message, reply.Error.Error)
			require.Equal(t, 500, reply.Error.Code)
			entries := logs.FilterMessage(tc.message).All()
			require.Len(t, entries, 1)
			require.NotEmpty(t, entries[0].ContextMap()["error"])
		})
	}
}

func TestAttestorFailureLogsCauseWithoutChangingReply(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
	cause := errors.New("NSM device unavailable")
	open := func() (attestor.Attestor, func(), error) { return nil, nil, cause }
	var out bytes.Buffer
	require.NoError(t, Serve(strings.NewReader(`{"Gateway":{"URL":"https://gateway.example"}}`), &out, lggr, open))
	reply, err := worker.DecodeReply(out.Bytes())
	require.NoError(t, err)
	require.Equal(t, "cannot open worker attestor", reply.Error.Error)
	require.Equal(t, 500, reply.Error.Code)
	require.NotContains(t, out.String(), cause.Error())
	entries := logs.FilterMessage("cannot open worker attestor").All()
	require.Len(t, entries, 1)
	require.Equal(t, cause.Error(), entries[0].ContextMap()["error"])
}

func TestProtocolErrorsPreserveCause(t *testing.T) {
	lggr := logger.Test(t)
	err := Serve(iotest.ErrReader(io.ErrUnexpectedEOF), io.Discard, lggr, nil)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	err = Serve(strings.NewReader("{"), io.Discard, lggr, nil)
	var syntax *json.SyntaxError
	require.ErrorAs(t, err, &syntax)
}
