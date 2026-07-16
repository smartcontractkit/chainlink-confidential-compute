//go:build wasip1

package main

import (
	"log/slog"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
)

type Result struct {
	StatusCode uint32
	Body       string
}

func subscribe(_ string, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[string], error) {
	return cre.Workflow[string]{
		cre.HandlerInTee(
			basictrigger.Trigger(&basictrigger.Config{Number: 100, Name: "test"}),
			handleTrigger,
			cre.AnyTee{},
		),
	}, nil
}

func handleTrigger(targetURL string, runtime cre.TeeRuntime, _ *basictrigger.Outputs) (*Result, error) {
	httpReq := &http.Request{
		Url:    targetURL,
		Method: "POST",
		Body:   []byte("hello from wasm"),
		MultiHeaders: map[string]*http.HeaderValues{
			"Content-Type": {Values: []string{"text/plain"}},
		},
	}
	client := &http.Client{}
	reply, err := client.SendRequestInTee(runtime, httpReq).Await()
	if err != nil {
		return nil, err
	}

	return &Result{
		StatusCode: reply.StatusCode,
		Body:       string(reply.Body),
	}, nil

}

func main() {
	wasm.NewRunner(func(bs []byte) (string, error) { return string(bs), nil }).Run(subscribe)
}
