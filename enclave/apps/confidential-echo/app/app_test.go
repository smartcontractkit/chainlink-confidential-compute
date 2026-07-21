package app_test

import (
	"net/http"
	"testing"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-echo/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/emitter"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEchoEnclaveApp_Execute(t *testing.T) {
	var requestID [32]byte

	tests := []struct {
		name       string
		appID      string
		input      string
		secrets    map[string][]byte
		wantOutput string
		wantErr    bool
	}{
		{
			name:       "substitutes a secret",
			appID:      types.AppIDConfidentialEcho,
			input:      "hello {{.name}}",
			secrets:    map[string][]byte{"name": []byte("Alice")},
			wantOutput: "hello Alice",
		},
		{
			name:       "substitutes multiple secrets",
			appID:      types.AppIDConfidentialEcho,
			input:      "{{.greeting}}, {{.name}}!",
			secrets:    map[string][]byte{"greeting": []byte("hi"), "name": []byte("Bob")},
			wantOutput: "hi, Bob!",
		},
		{
			name:       "no secrets, plain passthrough",
			appID:      types.AppIDConfidentialEcho,
			input:      "static output",
			secrets:    nil,
			wantOutput: "static output",
		},
		{
			name:    "wrong app ID is rejected",
			appID:   "some-other-app@1.0.0",
			input:   "hello {{.name}}",
			secrets: map[string][]byte{"name": []byte("Alice")},
			wantErr: true,
		},
		{
			name:    "missing secret key errors",
			appID:   types.AppIDConfidentialEcho,
			input:   "hello {{.name}}",
			secrets: nil,
			wantErr: true,
		},
		{
			name:    "malformed template errors",
			appID:   types.AppIDConfidentialEcho,
			input:   "hello {{.name",
			secrets: map[string][]byte{"name": []byte("Alice")},
			wantErr: true,
		},
	}

	echoApp := app.NewEchoEnclaveApp()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, execErr := echoApp.Execute(requestID, tt.appID, []byte(tt.input), tt.secrets, emitter.NewNoOpEmitter())
			if tt.wantErr {
				require.NotNil(t, execErr)
				assert.Equal(t, http.StatusBadRequest, execErr.Code)
				return
			}
			require.Nil(t, execErr)
			assert.Equal(t, tt.wantOutput, string(output))
		})
	}
}
