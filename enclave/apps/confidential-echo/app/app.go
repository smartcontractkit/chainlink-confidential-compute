package app

import (
	"fmt"
	"net/http"
	"strings"
	texttemplate "text/template"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// echoEnclaveApp is a minimal reference implementation of the EnclaveApp
// interface. It treats the public input as a Go text/template and renders it
// with the injected secrets substituted by name, returning the rendered bytes.
// It performs no network access and has no external dependencies, so it serves
// as the canonical example of the secret-injection pattern.
type echoEnclaveApp struct{}

var _ types.EnclaveApp = (*echoEnclaveApp)(nil)

// NewEchoEnclaveApp returns a reference EnclaveApp that renders its public input
// template with the injected secrets.
func NewEchoEnclaveApp() types.EnclaveApp {
	return &echoEnclaveApp{}
}

func (a *echoEnclaveApp) Execute(_ [32]byte, appID string, inputData []byte, secretsMap map[string][]byte, emitter types.Emitter, _ ...types.SignedComputeRequest) ([]byte, *types.ExecuteError) {
	if appID != types.AppIDConfidentialEcho {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("invalid app ID: expected %s, got %s", types.AppIDConfidentialEcho, appID),
			Code:  http.StatusBadRequest,
		}
	}

	tmpl, err := texttemplate.New("echo").Option("missingkey=error").Parse(string(inputData))
	if err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("error parsing template: %s", err.Error()),
			Code:  http.StatusBadRequest,
		}
	}

	templateData := make(map[string]string, len(secretsMap))
	for name, value := range secretsMap {
		templateData[name] = string(value)
	}

	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, templateData); err != nil {
		return nil, &types.ExecuteError{
			Error: fmt.Sprintf("error rendering template: %s", err.Error()),
			Code:  http.StatusBadRequest,
		}
	}

	emitter.Emit("echo_completed", map[string]any{
		"output_bytes": rendered.Len(),
	})

	return []byte(rendered.String()), nil
}
