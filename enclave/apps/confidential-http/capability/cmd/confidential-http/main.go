package main

import (
	"github.com/smartcontractkit/capabilities/libs/loopserver"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-http/capability"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialhttp/server"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
)

func main() {
	loopserver.ServeNew(capability.ServiceName, func(s *loop.Server) loop.StandardCapabilities {
		return server.NewClientServer(capability.NewService(s.Logger, s.LimitsFactory))
	})
}
