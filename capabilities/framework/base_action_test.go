package framework

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	frameworktypes "github.com/smartcontractkit/confidential-compute/types/frameworktypes"
)

type testExecutorInput struct{}

func (t *testExecutorInput) GetInput() proto.Message { return &TestInput{} }

func (t *testExecutorInput) GetVaultDonSecrets() []*frameworktypes.SecretIdentifier { return nil }

func TestBaseConfidentialAction_Initialise_CreatesExecutor(t *testing.T) {
	action := NewConfidentialAction[*testExecutorInput](
		logger.Test(t),
		"test-service",
		"test service",
		"test-capability-id",
		"test-version",
		limits.Factory{},
		func() *TestOutput { return &TestOutput{} },
	)

	err := action.Initialise(context.Background(), core.StandardCapabilitiesDependencies{})
	require.NoError(t, err)
}
