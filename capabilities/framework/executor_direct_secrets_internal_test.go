package framework

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/actions/vault"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/settings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	frameworktypes "github.com/smartcontractkit/chainlink-confidential-compute/types/frameworktypes"
)

const (
	directSecretsEnabledPeriod  = "[2020-01-01 00:00:00 +0000 UTC,2100-01-01 00:00:00 +0000 UTC]"
	directSecretsDisabledPeriod = "[2100-01-01 00:00:00 +0000 UTC,2101-01-01 00:00:00 +0000 UTC]"
)

type mapSettings map[string]string

func (m mapSettings) GetScoped(_ context.Context, _ settings.Scope, key string) (string, error) {
	return m[key], nil
}

type errorSettings struct{}

func (errorSettings) GetScoped(_ context.Context, _ settings.Scope, _ string) (string, error) {
	return "", errors.New("settings unavailable")
}

func newDirectSecretsTestExecutor(t *testing.T, getter settings.Getter) *RealExecutor {
	t.Helper()
	return &RealExecutor{
		lggr:          logger.Test(t),
		limitsFactory: limits.Factory{Settings: getter},
	}
}

func directSecretsMetadata(ts time.Time) capabilities.RequestMetadata {
	return capabilities.RequestMetadata{
		WorkflowID:          "workflow-id",
		WorkflowOwner:       "0x0000000000000000000000000000000000000001",
		OrgID:               "org-id",
		WorkflowExecutionID: "execution-id",
		ExecutionTimestamp:  ts,
	}
}

func TestGetSecretsDirectlyEnabled(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		ccGate      string
		globalGate  string
		executionTS time.Time
		want        bool
	}{
		{
			name:        "both gates enabled",
			ccGate:      directSecretsEnabledPeriod,
			globalGate:  directSecretsEnabledPeriod,
			executionTS: now,
			want:        true,
		},
		{
			name:        "capability gate disabled",
			ccGate:      directSecretsDisabledPeriod,
			globalGate:  directSecretsEnabledPeriod,
			executionTS: now,
			want:        false,
		},
		{
			name:        "global gate disabled",
			ccGate:      directSecretsEnabledPeriod,
			globalGate:  directSecretsDisabledPeriod,
			executionTS: now,
			want:        false,
		},
		{
			name:        "both gates disabled",
			ccGate:      directSecretsDisabledPeriod,
			globalGate:  directSecretsDisabledPeriod,
			executionTS: now,
			want:        false,
		},
		{
			name:        "execution timestamp before capability gate",
			ccGate:      "[2027-01-01 00:00:00 +0000 UTC,2100-01-01 00:00:00 +0000 UTC]",
			globalGate:  directSecretsEnabledPeriod,
			executionTS: now,
			want:        false,
		},
		{
			name:        "zero execution timestamp",
			ccGate:      directSecretsEnabledPeriod,
			globalGate:  directSecretsEnabledPeriod,
			executionTS: time.Time{},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := newDirectSecretsTestExecutor(t, mapSettings{
				"ConfidentialCompute.ConfidentialHTTPVaultGetSecretsDirectlyActivePeriod": tt.ccGate,
				"PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod":                  tt.globalGate,
			})

			got := executor.getSecretsDirectlyEnabled(t.Context(), directSecretsMetadata(tt.executionTS))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetSecretsDirectlyEnabledSettingsError(t *testing.T) {
	executor := newDirectSecretsTestExecutor(t, errorSettings{})

	got := executor.getSecretsDirectlyEnabled(t.Context(), directSecretsMetadata(time.Now()))
	require.False(t, got)
}

type noopEmitter struct{}

func (noopEmitter) Emit(string, map[string]any) {}

type fakeVaultCapability struct {
	got *vault.GetSecretsRequest
}

func (f *fakeVaultCapability) Info(context.Context) (capabilities.CapabilityInfo, error) {
	return capabilities.CapabilityInfo{}, nil
}

func (f *fakeVaultCapability) RegisterToWorkflow(context.Context, capabilities.RegisterToWorkflowRequest) error {
	return nil
}

func (f *fakeVaultCapability) UnregisterFromWorkflow(context.Context, capabilities.UnregisterFromWorkflowRequest) error {
	return nil
}

func (f *fakeVaultCapability) Execute(_ context.Context, req capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	f.got = &vault.GetSecretsRequest{}
	if err := req.Payload.UnmarshalTo(f.got); err != nil {
		return capabilities.CapabilityResponse{}, err
	}

	enclaveKey := hex.EncodeToString([]byte("enclave-public-key"))
	resp := &vault.GetSecretsResponse{
		Responses: []*vault.SecretResponse{{
			Id: &vault.SecretIdentifier{
				Key:       "secret-key",
				Namespace: "main",
				Owner:     "0x0000000000000000000000000000000000000001",
			},
			Result: &vault.SecretResponse_Data{Data: &vault.SecretData{
				EncryptedValue: hex.EncodeToString([]byte("ciphertext")),
				EncryptedDecryptionKeyShares: []*vault.EncryptedShares{{
					EncryptionKey: enclaveKey,
					BinaryShares:  [][]byte{[]byte("share")},
				}},
			}},
		}},
	}
	payload, err := anypb.New(resp)
	if err != nil {
		return capabilities.CapabilityResponse{}, err
	}
	return capabilities.CapabilityResponse{Payload: payload}, nil
}

func TestGetEncryptedDecryptionSharesSetsDirectFlag(t *testing.T) {
	tests := []struct {
		name       string
		ccGate     string
		globalGate string
		want       bool
	}{
		{
			name:       "gates enabled",
			ccGate:     directSecretsEnabledPeriod,
			globalGate: directSecretsEnabledPeriod,
			want:       true,
		},
		{
			name:       "capability gate disabled",
			ccGate:     directSecretsDisabledPeriod,
			globalGate: directSecretsEnabledPeriod,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeVault := &fakeVaultCapability{}
			executor := &RealExecutor{
				lggr: logger.Test(t),
				limitsFactory: limits.Factory{Settings: mapSettings{
					"ConfidentialCompute.ConfidentialHTTPVaultGetSecretsDirectlyActivePeriod": tt.ccGate,
					"PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod":                  tt.globalGate,
				}},
				vaultDON: VaultDON{
					CryptographyThreshold: 1,
					Capability:            fakeVault,
				},
				capConfig: &ParsedConfig{EnableSecretsCache: false},
			}

			_, _, _, err := executor.GetEncryptedDecryptionShares(
				t.Context(),
				logger.Test(t),
				[]*frameworktypes.SecretIdentifier{{Key: "secret-key", Namespace: "main"}},
				[]byte("enclave-public-key"),
				directSecretsMetadata(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)),
				noopEmitter{},
			)
			require.NoError(t, err)
			require.NotNil(t, fakeVault.got)
			assert.Equal(t, tt.want, fakeVault.got.GetSecretsDirectly)
		})
	}
}
