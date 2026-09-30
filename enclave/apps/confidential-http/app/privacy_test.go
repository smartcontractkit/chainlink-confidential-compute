package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	enclavetypes "github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/server"
	httpsmocks "github.com/smartcontractkit/chainlink-confidential-compute/enclave/testutil"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type privateErrorBody struct{ secret string }

func (b privateErrorBody) Read([]byte) (int, error) { return 0, errors.New(b.secret) }
func (b privateErrorBody) Close() error             { return errors.New(b.secret) }

func TestHTTPEnclaveApp_Execute_RedactsHTTPFailures(t *testing.T) {
	const secret = "confidential-canary"
	tests := []struct {
		name string
		err  error
		body io.ReadCloser
		want string
	}{
		{name: "certificate", err: &tls.CertificateVerificationError{Err: x509.HostnameError{Host: secret, Certificate: &x509.Certificate{}}}, want: "error making http request: TLS certificate verification failed"},
		{name: "TLS integrity alert", err: &net.OpError{Op: "remote error", Err: tls.AlertError(20)}, want: "error making http request: transport failure"},
		{name: "unknown transport", err: errors.New(secret), want: "error making http request: transport failure"},
		{name: "read response", body: privateErrorBody{secret}, want: "error reading http response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs strings.Builder
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			client := httpsmocks.NewMockHTTPClientWithCustomResponse(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, secret, req.Header.Get("Authorization"))
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, secret, string(body))
				if tt.err != nil {
					return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: tt.err}
				}
				return &http.Response{StatusCode: http.StatusOK, Body: tt.body}, nil
			})
			app := NewHTTPEnclaveApp(client)
			input, err := proto.Marshal(&enclavetypes.Request{
				Method: http.MethodPost, Url: "https://example.com/" + secret + "?token=" + secret,
				MultiHeaders: map[string]*enclavetypes.HeaderValues{"Authorization": {Values: []string{"{{.token}}"}}},
				Body:         &enclavetypes.Request_BodyString{BodyString: "{{.token}}"},
			})
			require.NoError(t, err)
			em := server.NewResponseEmitter()
			output, execErr := app.Execute([32]byte{1}, types.AppIDConfidentialHTTP, input, map[string][]byte{"token": []byte(secret)}, em)
			require.NotNil(t, execErr)
			assert.Nil(t, output)
			assert.Equal(t, http.StatusBadRequest, execErr.Code)
			assert.Equal(t, "error in request 0: "+tt.want, execErr.Error)
			em.Emit("app_execution_failed", map[string]any{"error": execErr})
			metrics, events := em.Snapshot()
			wire, err := json.Marshal(types.EnclaveErrorResponse{Error: execErr.Error, Metrics: metrics, MetricEvents: events})
			require.NoError(t, err)
			assert.NotContains(t, string(wire), secret)
			assert.NotContains(t, logs.String(), secret)
		})
	}
}
