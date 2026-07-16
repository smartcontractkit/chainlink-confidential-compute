//go:build wasip1

// Package main is a v2 CRE workflow WASM binary for testing the engine path:
// syncer -> ConfidentialModule -> confidential-workflows capability -> enclave ->
// WASM -> GetSecrets + CallCapability(http-actions@1.0.0-alpha) +
// CallCapability(basic-test-action@1.0.0 via DON) -> relay DON -> basic action capability.
//
// The trigger runs in a TEE (any type). On Subscribe the SDK registers the cron
// trigger; on Trigger the TEE callback fetches a secret, optionally calls
// http-actions, and calls basic-test-action via the DON runtime.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	httpcap "github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basicaction"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
)

// Config is parsed from the JSON blob passed as ExecuteRequest.Config.
type Config struct {
	EchoURL string `json:"echo_url"`
}

func parseConfig(b []byte) (Config, error) {
	var cfg Config
	if len(b) > 0 {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("unmarshaling config JSON: %w", err)
		}
	}
	return cfg, nil
}

func subscribe(_ Config, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[Config], error) {
	return cre.Workflow[Config]{
		cre.HandlerInTee(
			basictrigger.Trigger(&basictrigger.Config{Number: 100, Name: "test"}),
			handleTrigger,
			cre.AnyTee{},
		),
	}, nil
}

func handleTrigger(config Config, runtime cre.TeeRuntime, _ *basictrigger.Outputs) (map[string]any, error) {
	secret, err := runtime.GetSecret(&cre.SecretRequest{Id: "MOCK_SECRET"}).Await()
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}
	secretValue := secret.Value

	result := map[string]any{"echo": "engine-test", "secret": secretValue}

	if config.EchoURL != "" {
		httpClient := &httpcap.Client{}
		httpResp, err := httpClient.SendRequestInTee(runtime, &httpcap.Request{
			Url:    config.EchoURL,
			Method: "POST",
			Body:   []byte("hello from engine-test"),
			MultiHeaders: map[string]*httpcap.HeaderValues{
				"Authorization": {Values: []string{secretValue}},
				"Content-Type":  {Values: []string{"text/plain"}},
			},
		}).Await()
		if err != nil {
			return nil, fmt.Errorf("http request: %w", err)
		}
		result["http_status"] = httpResp.StatusCode
		result["http_body"] = string(httpResp.Body)
	}

	basicActionClient := &basicaction.BasicAction{}
	if _, err := basicActionClient.PerformAction(runtime.UsingTheDons(), &basicaction.Inputs{InputThing: true}).Await(); err != nil {
		return nil, fmt.Errorf("basic action: %w", err)
	}

	return result, nil
}

func main() {
	wasm.NewRunner(parseConfig).Run(subscribe)
}
