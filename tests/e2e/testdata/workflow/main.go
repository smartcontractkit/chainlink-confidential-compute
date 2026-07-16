//go:build wasip1

// Package main is the E2E test workflow used by the engine-path test.
// It exercises two capability paths from inside a confidential workflow:
//   - GetSecret → VaultDON (remote dispatch through the relay DON)
//   - http.SendRequest + ConsensusMedianAggregation → intercepted locally
//     by the enclave (http-actions + consensus/Simple both handled in-process)
//
// Each success is marked in the workflow engine logs for the test to scrape.
package main

import (
	"log/slog"

	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/scheduler/cron"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
)

type config struct {
	EchoURL string `json:"echo_url"`
}

func main() {
	wasm.NewRunner(cre.ParseJSON[config]).Run(initWorkflow)
}

func initWorkflow(_ *config, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[*config], error) {
	return cre.Workflow[*config]{
		cre.HandlerInTee(
			cron.Trigger(&cron.Config{Schedule: "*/30 * * * * *"}),
			handleTrigger,
			cre.AnyTee{},
		),
	}, nil
}

func handleTrigger(cfg *config, trt cre.TeeRuntime, _ *cron.Payload) (any, error) {
	secret, err := trt.GetSecret(&sdkpb.SecretRequest{Id: "MOCK_SECRET"}).Await()
	if err != nil {
		return nil, err
	}
	// DO NOT log secrets in production workflows. We only do it here so the
	// test can scrape the value out of workflow-DON logs and confirm that the
	// VaultDON-routed secret-fetch path actually delivered the right value
	// into the WASM. Real users: don't follow this pattern.
	trt.Logger().Info("engine-test-secret", "value", secret.Value)

	result := map[string]any{"secret": secret.Value}

	if cfg.EchoURL != "" {
		client := &http.Client{}
		status, httpErr := fetchEchoStatus(cfg, trt, client)
		if httpErr != nil {
			trt.Logger().Error("engine-test-http-failed", "error", httpErr.Error())
			return nil, httpErr
		}
		trt.Logger().Info("engine-test-http", "status", status, "url", cfg.EchoURL)
		result["http_status"] = status
	}

	return result, nil
}

func fetchEchoStatus(cfg *config, trt cre.TeeRuntime, client *http.Client) (int32, error) {
	resp, err := client.SendRequestInTee(trt, &http.Request{
		Url:    cfg.EchoURL,
		Method: "POST",
		Body:   []byte("hello from engine-test"),
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
	}).Await()
	if err != nil {
		return 0, err
	}
	return int32(resp.StatusCode), nil
}
