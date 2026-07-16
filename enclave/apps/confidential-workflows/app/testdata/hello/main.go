//go:build wasip1

package main

import (
	"log/slog"

	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
)

func subscribe(_ []byte, _ *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[[]byte], error) {
	return cre.Workflow[[]byte]{
		cre.HandlerInTee(
			basictrigger.Trigger(&basictrigger.Config{Number: 100, Name: "test"}),
			handleTrigger,
			cre.AnyTee{},
		),
	}, nil
}

func handleTrigger(_ []byte, _ cre.TeeRuntime, _ *basictrigger.Outputs) (string, error) {
	return "hello from enclave wasm", nil
}

func main() {
	wasm.NewRunner(func(bs []byte) ([]byte, error) { return bs, nil }).Run(subscribe)
}
