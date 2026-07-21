package job

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"

	capabilitiespb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/pb"
	kcr "github.com/smartcontractkit/chainlink-evm/gethwrappers/keystone/generated/capabilities_registry_1_1_0"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	keystone_changeset "github.com/smartcontractkit/chainlink/deployment/keystone/changeset"

	"github.com/smartcontractkit/chainlink/system-tests/lib/cre"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/capabilities"
	"github.com/smartcontractkit/chainlink/system-tests/lib/cre/flags"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

var jobsDelivered = make(map[string]bool)

// ResetDeliveryState clears the jobsDelivered guard so that job specs
// can be re-delivered when a new CRE environment is created (e.g. across subtests).
func ResetDeliveryState() {
	jobsDelivered = make(map[string]bool)
}

var jobTemplate = `
type = "standardcapabilities"
schemaVersion = 1
externalJobID = "%s"
forwardingAllowed = false
command = "%s"
name = "%s"
config = %s
`

func New(name, version, binaryName string, enclaves []types.Enclave) (*capabilities.Capability, error) {
	return capabilities.New( //nolint:staticcheck // SA1019 ignore deprecation
		name,
		capabilities.WithJobSpecFn(jobSpec(name, binaryName)),
		capabilities.WithCapabilityRegistryV2ConfigFn(getRegisterWithV1ConfigFunc(name, version, enclaves)),
	)
}

func jobSpec(name string, binaryName string) cre.JobSpecFn {
	return func(input *cre.JobSpecInput) (cre.DonJobs, error) {

		// TODO: find out why this is getting called multiple times in the new topology.
		if jobsDelivered[name] {
			return nil, nil
		}
		jobsDelivered[name] = true

		donJobs := make(cre.DonJobs, 0)
		for _, don := range input.Dons.List() {
			if !don.HasFlag(name) {
				continue
			}

			workerNodes, wErr := don.Workers()
			if wErr != nil {
				return nil, errors.Wrap(wErr, "failed to find worker nodes")
			}

			var encryptedAPIKeys []string
			for _, workerNode := range workerNodes {
				// Get the workflow public encryption key from the node.
				client := workerNode.Clients.RestClient.APIClient.GetClient()
				req, err := http.NewRequestWithContext(context.Background(), "GET", workerNode.Clients.RestClient.APIClient.BaseURL+"/v2/keys/workflow", nil)
				if err != nil {
					return nil, errors.Wrap(err, "failed to create request to get workflow keys")
				}
				req.AddCookie(workerNode.Clients.RestClient.APIClient.Cookies[0])
				resp, err := client.Do(req)
				if err != nil {
					return nil, errors.Wrap(err, "failed to send request to get workflow keys")
				}
				defer util.SafeClose(resp)
				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("expected 200 OK from get workflow keys request, got %d", resp.StatusCode)
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, errors.Wrap(err, "failed to read response body from get workflow keys request")
				}
				var workflowKeysResp struct {
					Data []struct {
						Attributes struct {
							PublicKey string `json:"publicKey"`
						} `json:"attributes"`
					} `json:"data"`
				}
				if err := json.Unmarshal(body, &workflowKeysResp); err != nil {
					return nil, errors.Wrap(err, "failed to unmarshal workflow keys response")
				}
				if len(workflowKeysResp.Data) == 0 {
					return nil, errors.New("no workflow keys found in response")
				}
				publicKeyHex := workflowKeysResp.Data[0].Attributes.PublicKey
				publicKeyBytes, err := hex.DecodeString(publicKeyHex)
				if err != nil {
					return nil, errors.Wrap(err, "failed to decode public key hex")
				}
				if len(publicKeyBytes) != 32 {
					return nil, fmt.Errorf("expected public key to be 32 bytes, got %d", len(publicKeyBytes))
				}
				var publicKey [32]byte
				copy(publicKey[:], publicKeyBytes)

				// A real API key is not needed for e2e tests, but using a fake one ensures decryption works.
				var apiKey = "foobar"

				// Encrypt the API key with the workflow public key.
				ctxt, err := box.SealAnonymous(nil, []byte(apiKey), &publicKey, rand.Reader)
				if err != nil {
					return nil, errors.Wrap(err, "failed to seal API key")
				}
				encodedCtxt := hex.EncodeToString(ctxt)
				encryptedAPIKeys = append(encryptedAPIKeys, encodedCtxt)
			}

			for _, workerNode := range workerNodes {
				// Keep liveness detection aggressive in e2e so failover traffic starts only
				// after each node has had a chance to observe a dead enclave.
				config := map[string]any{
					"InsecureSkipTLSVerify":  true,
					"EncryptedAPIKeys":       strings.Join(encryptedAPIKeys, ","),
					"EnableCache":            true,
					"EnableProactiveRefresh": true,
					"MaxRetries":             3,
					"RetryBackoffSeconds":    5,
				}
				configBytes, err := json.Marshal(config)
				if err != nil {
					return nil, errors.Wrap(err, "failed to marshal e2e capability config")
				}
				c2 := fmt.Sprintf("'%s'", string(configBytes))
				donJobs = append(donJobs, &jobv1.ProposeJobRequest{
					NodeId: workerNode.JobDistributorDetails.NodeID,
					Spec:   fmt.Sprintf(jobTemplate, uuid.NewString(), binaryName, name, c2),
				})
			}
		}

		return donJobs, nil
	}
}

func getRegisterWithV1ConfigFunc(name string, version string, enclaves []types.Enclave) cre.CapabilityRegistryConfigFn {
	return func(donFlags []string, _ *cre.NodeSet) ([]keystone_changeset.DONCapabilityWithConfig, error) {
		var capabilities []keystone_changeset.DONCapabilityWithConfig

		config := types.EnclavesList{
			Enclaves: enclaves,
		}
		wrappedConfig, err := values.WrapMap(config)
		if err != nil {
			return nil, errors.Wrap(err, "failed to wrap default config")
		}

		if flags.HasFlag(donFlags, name) {
			capabilities = append(capabilities, keystone_changeset.DONCapabilityWithConfig{
				Capability: kcr.CapabilitiesRegistryCapability{
					LabelledName:   name,
					Version:        version,
					CapabilityType: 1, // ACTION
				},
				Config: &capabilitiespb.CapabilityConfig{
					DefaultConfig: values.Proto(wrappedConfig).GetMapValue(),
					LocalOnly:     true,
				},
			})
		}

		return capabilities, nil
	}
}
