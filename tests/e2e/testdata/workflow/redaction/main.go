//go:build wasip1

package main

import (
	"fmt"
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/confidentialhttp"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"

	"github.com/smartcontractkit/chainlink-confidential-compute/tests/e2e/testdata/workflow/redaction/input"
)

type config struct {
	App           string `json:"app"`
	AuthorizedKey string `json:"authorizedKey"`
}

func subscribe(c *config, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[*config], error) {
	if !common.IsHexAddress(c.AuthorizedKey) || common.HexToAddress(c.AuthorizedKey) == (common.Address{}) {
		return nil, fmt.Errorf("authorizedKey must be a nonzero EVM address")
	}
	trigger := http.Trigger(&http.Config{AuthorizedKeys: []*http.AuthorizedKey{{
		Type: http.KeyType_KEY_TYPE_ECDSA_EVM, PublicKey: c.AuthorizedKey,
	}}})
	switch c.App {
	case "confidential-http":
		return cre.Workflow[*config]{cre.Handler(trigger, runHTTP)}, nil
	case "confidential-workflows":
		return cre.Workflow[*config]{cre.HandlerInTee(trigger, runTEE,
			cre.OneOfTees{cre.Nitro{Regions: []cre.NitroRegion{cre.NitroUsWest2}}})}, nil
	default:
		return nil, fmt.Errorf("app must be confidential-http or confidential-workflows")
	}
}

func runHTTP(c *config, rt cre.Runtime, payload *http.Payload) (string, error) {
	caseName, url, err := input.RequestURL(payload.Input)
	if err != nil {
		return "", err
	}
	rt.Logger().Info("HTTP redaction smoke started", "app", c.App, "case", caseName)
	client := &confidentialhttp.Client{}
	resp, err := client.SendRequest(rt, &confidentialhttp.ConfidentialHTTPRequest{
		Request: &confidentialhttp.HTTPRequest{
			Url: url, Method: "GET",
			MultiHeaders: map[string]*confidentialhttp.HeaderValues{"Authorization": {Values: []string{"Bearer " + input.Marker}}},
		},
	}).Await()
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("redaction smoke expected a hard failure, got HTTP %d", resp.StatusCode)
}

func runTEE(c *config, rt cre.TeeRuntime, payload *http.Payload) (string, error) {
	caseName, url, err := input.RequestURL(payload.Input)
	if err != nil {
		return "", err
	}
	rt.Logger().Info("HTTP redaction smoke started", "app", c.App, "case", caseName)
	client := &http.Client{}
	resp, err := client.SendRequestInTee(rt, &http.Request{
		Url: url, Method: "GET",
		MultiHeaders: map[string]*http.HeaderValues{"Authorization": {Values: []string{"Bearer " + input.Marker}}},
	}).Await()
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("redaction smoke expected a hard failure, got HTTP %d", resp.StatusCode)
}

func main() {
	wasm.NewRunner(cre.ParseJSON[config]).Run(subscribe)
}
