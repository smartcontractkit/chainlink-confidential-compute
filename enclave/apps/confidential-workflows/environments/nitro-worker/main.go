package main

import (
	"os"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/internal/workerexec"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
)

func main() { os.Exit(workerexec.Main(nitro.OpenNitroAttestor)) }
