package main

import (
	"os"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/workerexec"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/fake/runner"
)

func main() { os.Exit(workerexec.Main(runner.OpenFakeAttestor)) }
