//go:build wasip1

// spin is a workflow that never returns: it burns CPU in the handler with no
// host calls, so only the WASM host's epoch deadline can stop it. Used to test
// the enclave's execution timeout.
package main

import (
	"log/slog"
	"strconv"

	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
	"github.com/smartcontractkit/cre-sdk-go/internal_testing/capabilities/basictrigger"
)

// sink keeps the loop below from being optimized away.
var sink uint64

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
	for {
		sink++
		if sink == 0 { // unreachable in practice; keeps the compiler honest
			return strconv.FormatUint(sink, 10), nil
		}
	}
}

func main() {
	wasm.NewRunner(func(bs []byte) ([]byte, error) { return bs, nil }).Run(subscribe)
}
