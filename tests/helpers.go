package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ethereum/go-ethereum/node"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	enclaveclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/require"
)

var (
	simulatedChainID = big.NewInt(1337)
	localRPCHTTPPort = 8545
	localRPCWSPort   = 8546
	localRPCHTTP     = fmt.Sprintf("http://localhost:%d", localRPCHTTPPort)
	localRPCWS       = fmt.Sprintf("ws://localhost:%d", localRPCWSPort)
)

type TDH2KeyStorage struct {
	MasterPublicKey []byte   `json:"master_public_key"`
	MasterSecret    []byte   `json:"master_secret,omitempty"`
	PrivateShares   [][]byte `json:"private_shares"`
	Threshold       int      `json:"threshold"`
	NumParties      int      `json:"num_parties"`
}

type SigningKeyStorage struct {
	PrivateKeys [][]byte `json:"private_keys"`
	PublicKeys  [][]byte `json:"public_keys"`
	NodeCount   int      `json:"node_count"`
}

type EnclavePublicKeyStorage struct {
	EnclavePublicKey []byte `json:"enclave_public_key"`
}

type NodeInfo struct {
	URL        string `json:"url"`
	InstanceID string `json:"instance_id"`
}

func mustGenerateEd25519Keys(t *testing.T, nodeCount int) (keyStorage SigningKeyStorage) {
	for i := 0; i < nodeCount; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keyStorage.PublicKeys = append(keyStorage.PublicKeys, pubKey)
		keyStorage.PrivateKeys = append(keyStorage.PrivateKeys, privKey)
	}
	return keyStorage
}

func mustGenerateTDH2Keys(t *testing.T, threshold int, numParties int) (keystorage TDH2KeyStorage) {
	masterSecret, masterPublicKey, privateShares, err := tdh2easy.GenerateKeys(threshold, numParties)
	require.NoError(t, err)

	keystorage.MasterPublicKey, err = masterPublicKey.Marshal()
	require.NoError(t, err)
	keystorage.MasterSecret, err = masterSecret.Marshal()
	require.NoError(t, err)
	var privSharesBytes [][]byte
	for _, prs := range privateShares {
		prsByte, err := prs.Marshal()
		require.NoError(t, err)
		privSharesBytes = append(privSharesBytes, prsByte)
	}
	keystorage.PrivateShares = privSharesBytes
	keystorage.NumParties = numParties
	keystorage.Threshold = threshold

	return keystorage
}

func mustGetEnclavePublicKeys(t *testing.T, pubKeyResp []types.EnclavePublicKeyData) (keyStorage []EnclavePublicKeyStorage) {
	// Use most recent public key from each enclave.
	for _, pkResp := range pubKeyResp {
		require.GreaterOrEqual(t, len(pkResp.PublicKeys), 1)
		var newestPubKeyIndex *int = nil
		for i := range pkResp.PublicKeys {
			if newestPubKeyIndex == nil || pkResp.CreationTimes[i].Before(pkResp.CreationTimes[*newestPubKeyIndex]) {
				newestPubKeyIndex = &i
			}
		}
		keyStorage = append(keyStorage, EnclavePublicKeyStorage{
			EnclavePublicKey: pkResp.PublicKeys[*newestPubKeyIndex],
		})
	}

	return keyStorage
}

func defaultRequestTimeoutResolver(_ context.Context, publicKey bool) (time.Duration, error) {
	if publicKey {
		return types.DefaultPublicKeyRequestTimeout, nil
	}
	return types.DefaultEnclaveRequestTimeout, nil
}

func newTestEnclavePool(nodes []types.Enclave, httpClient *http.Client) (enclaveclient.EnclaveClient, error) {
	return enclaveclient.NewPoolWithConfig(nodes, nil, httpClient, enclaveclient.PoolConfig{
		Cache:                    enclaveclient.DefaultCacheConfig,
		Session:                  enclaveclient.DefaultSessionConfig,
		RequestTimeoutResolverFn: defaultRequestTimeoutResolver,
	})
}

func encryptUserSecrets(secrets [][]byte, publicKey *tdh2easy.PublicKey) ([][]byte, error) {
	ciphertexts := make([][]byte, len(secrets))
	for i, secret := range secrets {
		ciphertext, err := tdh2easy.Encrypt(publicKey, secret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt secret %d: %v", i, err)
		}

		ciphertextBytes, err := ciphertext.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ciphertext %d: %v", i, err)
		}
		ciphertexts[i] = ciphertextBytes
	}
	return ciphertexts, nil
}

// prepareAndExecuteSignedRequests prepares signed compute requests for each enclave node and executes them concurrently.
func prepareAndExecuteSignedRequests(
	ctx context.Context,
	enclaveNodes []types.Enclave,
	enclaveIDs [][32]byte,
	reqID [32]byte,
	publicData []byte,
	userCiphertexts [][]byte,
	userCiphertextNames []string,
	keyStorage *TDH2KeyStorage,
	signingKeys *SigningKeyStorage,
	enclaveKeys []EnclavePublicKeyStorage,
	httpClient *http.Client,
	appID string,
	version string,
) ([]*types.ExecuteResponse, error) {
	var masterPublicKey tdh2easy.PublicKey
	if err := masterPublicKey.Unmarshal(keyStorage.MasterPublicKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal master public key: %w", err)
	}

	pool, err := newTestEnclavePool(enclaveNodes, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create enclave pool: %w", err)
	}

	signerCount := len(signingKeys.PublicKeys)
	if signerCount > len(signingKeys.PrivateKeys) {
		return nil, fmt.Errorf("not enough signing keys: have %d, need %d", len(signingKeys.PrivateKeys), signerCount)
	}

	// Precompute encrypted shares once per enclave key. In production, the upstream
	// vault DON computes these once and all nodes receive identical copies.
	// box.SealAnonymous uses rand.Reader, so we must compute once and share across signers.
	precomputedShares := make([][][][]byte, len(enclaveKeys))
	for enclaveIdx, enclaveKey := range enclaveKeys {
		encryptedShares := make([][][]byte, len(userCiphertexts))
		for ciphertextIdx, userCiphertextBytes := range userCiphertexts {
			var tdh2Ciphertext tdh2easy.Ciphertext
			if err := tdh2Ciphertext.UnmarshalVerify(userCiphertextBytes, &masterPublicKey); err != nil {
				return nil, fmt.Errorf("enclave %d: failed to unmarshal user ciphertext %d: %v", enclaveIdx, ciphertextIdx, err)
			}

			encryptedShares[ciphertextIdx] = make([][]byte, len(keyStorage.PrivateShares))
			for shareIdx, shareBytes := range keyStorage.PrivateShares {
				var privateShare tdh2easy.PrivateShare
				if err := privateShare.Unmarshal(shareBytes); err != nil {
					return nil, fmt.Errorf("enclave %d, ciphertext %d: failed to unmarshal private share %d: %v", enclaveIdx, ciphertextIdx, shareIdx, err)
				}

				enclaveEphemeralPubKeyBytes := [32]byte{}
				copy(enclaveEphemeralPubKeyBytes[:], enclaveKey.EnclavePublicKey)

				encryptedShare, err := util.TDH2NACLBoxComputeEncryptedDecryptionShare(privateShare, masterPublicKey, tdh2Ciphertext, enclaveEphemeralPubKeyBytes)
				if err != nil {
					return nil, fmt.Errorf("enclave %d, ciphertext %d, share %d: failed to compute encrypted decryption share: %v", enclaveIdx, ciphertextIdx, shareIdx, err)
				}
				encryptedShares[ciphertextIdx][shareIdx] = encryptedShare
			}
		}
		precomputedShares[enclaveIdx] = encryptedShares
	}

	var wg sync.WaitGroup
	responseChannel := make(chan *types.ExecuteResponse, signerCount*len(enclaveKeys))
	errorChannel := make(chan error, signerCount)

	for i := 0; i < signerCount; i++ {
		privKey := signingKeys.PrivateKeys[i]

		wg.Add(1)
		go func(signerIndex int, privKey []byte) {
			defer wg.Done()

			var signedReqsForThisSigner []types.SignedComputeRequest
			for enclaveIdx, enclaveKey := range enclaveKeys {
				computeReq := types.ComputeRequest{
					RequestID:                    reqID,
					PublicData:                   publicData,
					Ciphertexts:                  userCiphertexts,
					CiphertextNames:              userCiphertextNames,
					MasterPublicKey:              keyStorage.MasterPublicKey,
					EnclaveEphemeralPublicKey:    enclaveKey.EnclavePublicKey,
					EncryptedDecryptionKeyShares: precomputedShares[enclaveIdx],
					AppID:                        appID,
					Version:                      version,
				}

				hash := computeReq.Hash()
				prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
				signature := ed25519.Sign(privKey, prefixedHash)
				signedReqsForThisSigner = append(signedReqsForThisSigner, types.SignedComputeRequest{
					ComputeRequest: computeReq,
					Signature:      signature,
				})
			}

			if len(signedReqsForThisSigner) > 0 {
				responses, err := pool.ExecuteBatch(ctx, signedReqsForThisSigner, enclaveIDs)
				if err != nil {
					errorChannel <- fmt.Errorf("signer %d: failed to execute requests: %v", signerIndex, err)
					return
				}
				for i := range responses {
					responseChannel <- &responses[i]
				}
			}
		}(i, privKey)
	}

	wg.Wait()
	close(responseChannel)
	close(errorChannel)

	var collectedErrors []string
	for err := range errorChannel {
		if err != nil {
			collectedErrors = append(collectedErrors, err.Error())
		}
	}
	if len(collectedErrors) > 0 {
		return nil, fmt.Errorf("errors during request preparation/execution: %s", strings.Join(collectedErrors, "; "))
	}

	var allResponses []*types.ExecuteResponse
	for resp := range responseChannel {
		allResponses = append(allResponses, resp)
	}

	return allResponses, nil
}

// validateAndCoalesceResponses checks for response consistency and returns a representative response.
func validateAndCoalesceResponses(responses []*types.ExecuteResponse, nodeCount int, numEnclavesTargetedByEachSigner int) (*types.ExecuteResponse, error) {
	if len(responses) == 0 {
		return nil, fmt.Errorf("no successful responses received")
	}

	expectedTotalResponseCount := nodeCount * numEnclavesTargetedByEachSigner
	if len(responses) != expectedTotalResponseCount {
		return nil, fmt.Errorf("expected %d responses, but got %d (signers: %d, enclaves per signer: %d)",
			expectedTotalResponseCount, len(responses), nodeCount, numEnclavesTargetedByEachSigner)
	}

	firstResp := responses[0]
	for i := 1; i < len(responses); i++ {
		if !bytes.Equal(responses[i].RequestID[:], firstResp.RequestID[:]) ||
			!bytes.Equal(responses[i].Output, firstResp.Output) {
			return nil, fmt.Errorf("response %d (RequestID: %x) differs from the first response (RequestID: %x)",
				i, responses[i].RequestID, firstResp.RequestID)
		}
	}

	fmt.Printf("All %d responses received and verified\n", nodeCount)
	return firstResp, nil
}

func getMeasurements(measurementsFile string) ([]byte, error) {
	if measurementsFile == "" {
		return nil, fmt.Errorf("measurements file must be provided")
	}

	data, err := os.ReadFile(measurementsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read measurements file: %w", err)
	}

	var m nitro.Measurements
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse measurements file: %w", err)
	}

	// Decode PCR hex strings to []byte if needed, otherwise assume already []byte
	// If the JSON file contains hex strings, you need to decode them here.
	// If the JSON file contains base64-encoded []byte, json.Unmarshal will handle it.

	measurements, err := json.Marshal(m.Measurements)
	if err != nil {
		return nil, err
	}

	return measurements, nil
}

func getNodes(url string, trustedMeasurementsBin []byte) []types.Enclave {
	enclaveType := types.EnclaveTypeNitro
	if UseFakeEnclave() {
		enclaveType = types.EnclaveTypeFake
	}
	return []types.Enclave{{
		EnclaveURL:    url,
		EnclaveType:   enclaveType,
		TrustedValues: [][]byte{trustedMeasurementsBin},
	}}
}

// Configures the local RPC settings for a simulated blockchain.
func withLocalRPC() func(nodeConf *node.Config, ethConf *ethconfig.Config) {
	return func(nodeConf *node.Config, ethConf *ethconfig.Config) {
		nodeConf.HTTPHost = "localhost"
		nodeConf.WSHost = "localhost"
		nodeConf.HTTPPort = localRPCHTTPPort
		nodeConf.WSPort = localRPCWSPort
		nodeConf.HTTPModules = []string{"eth", "net", "web3", "debug", "txpool"}
		nodeConf.WSModules = []string{"eth", "net", "web3", "debug", "txpool"}
	}
}

// Sets up a local simulated blockchain, deploys a CapabilitiesRegistry contract,
// and adds a fake capability + a DON with the desired Peer IDs.
func setupLocalCapabilitiesRegistry(t *testing.T, peerIDs []string, f uint32) common.Address {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	owner, err := bind.NewKeyedTransactorWithChainID(key, simulatedChainID)
	require.NoError(t, err)
	b := simulated.NewBackend(gethTypes.GenesisAlloc{
		owner.From: {
			Balance: big.NewInt(0).Mul(big.NewInt(10), big.NewInt(1e18)),
		},
	}, simulated.WithBlockGasLimit(10e6), withLocalRPC())
	t.Cleanup(func() {
		err := b.Close()
		if err != nil {
			t.Logf("Failed to close simulated backend: %v", err)
		}
	})
	chainID, err := b.Client().ChainID(context.Background())
	require.NoError(t, err)
	require.Equal(t, simulatedChainID, chainID)

	peerIDsBytes := make([][32]byte, len(peerIDs))
	for i, hexPeerID := range peerIDs {
		peerBytes, err := hex.DecodeString(hexPeerID)
		require.NoError(t, err, "Failed to decode hex peer ID: %s", hexPeerID)
		peerIDsBytes[i] = [32]byte{}
		copy(peerIDsBytes[i][:], peerBytes)
	}

	capabilitiesRegistryAddr, _, capReg, err := capabilities_registry_wrapper_v2.DeployCapabilitiesRegistry(
		owner,
		b.Client(),
		capabilities_registry_wrapper_v2.CapabilitiesRegistryConstructorParams{CanAddOneNodeDONs: false},
	)
	require.NoError(t, err)
	b.Commit()
	_, err = capReg.AddCapabilities(
		owner,
		[]capabilities_registry_wrapper_v2.CapabilitiesRegistryCapability{{
			CapabilityId:          "confidential-compute@1.0.0",
			ConfigurationContract: common.Address{},
			Metadata:              []byte{},
		}},
	)
	require.NoError(t, err)
	b.Commit()
	cap, err := capReg.GetCapabilities(nil, big.NewInt(0), big.NewInt(10000))
	require.NoError(t, err)
	require.Len(t, cap, 1)

	_, err = capReg.AddNodeOperators(
		owner,
		[]capabilities_registry_wrapper_v2.CapabilitiesRegistryNodeOperatorParams{{
			Admin: owner.From,
			Name:  "admin",
		}},
	)
	require.NoError(t, err)
	b.Commit()

	var nodes []capabilities_registry_wrapper_v2.CapabilitiesRegistryNodeParams
	for i, p2pID := range peerIDsBytes {
		p := common.BytesToHash([]byte(fmt.Sprintf("capability-%d", i)))
		nodes = append(nodes, capabilities_registry_wrapper_v2.CapabilitiesRegistryNodeParams{
			NodeOperatorId:      1,
			Signer:              p,
			P2pId:               p2pID,
			EncryptionPublicKey: p,
			CsaKey:              p,
			CapabilityIds:       []string{cap[0].CapabilityId},
		})
	}
	_, err = capReg.AddNodes(owner, nodes)
	require.NoError(t, err)
	b.Commit()

	_, err = capReg.AddDONs(
		owner,
		[]capabilities_registry_wrapper_v2.CapabilitiesRegistryNewDONParams{{
			Name:  "don",
			Nodes: peerIDsBytes,
			CapabilityConfigurations: []capabilities_registry_wrapper_v2.CapabilitiesRegistryCapabilityConfiguration{{
				CapabilityId: cap[0].CapabilityId,
				Config:       []byte{},
			}},
			Config:           []byte{},
			F:                uint8(f),
			IsPublic:         true,
			AcceptsWorkflows: true,
		}})
	require.NoError(t, err)
	b.Commit()

	dons, err := capReg.GetDONs(nil, big.NewInt(0), big.NewInt(10000))
	require.NoError(t, err)
	for i, peerID := range dons[0].NodeP2PIds {
		t.Logf("DON peer ID %d: %s", i, hex.EncodeToString(peerID[:]))
		require.Contains(t, peerIDs, hex.EncodeToString(peerID[:]), "Expected peer ID not found in DON configuration")
	}
	require.Equal(t, dons[0].F, uint8(f))

	return capabilitiesRegistryAddr
}

// returns the parent directory of the test file
func findProjectRoot(t *testing.T) string {
	dir, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Dir(dir)
}

func readCertFilePEM(certPath string) ([]byte, error) {
	if certPath == "" {
		return nil, nil // No cert file to validate
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(cert) {
		return nil, fmt.Errorf("failed to parse certificate from bytes %s", string(cert))
	}
	return cert, nil
}

func getHTTPClient(certPath string) (*http.Client, error) {
	cert, err := readCertFilePEM(certPath)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return http.DefaultClient, nil
	}

	tlsConfig := &tls.Config{}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cert)
	tlsConfig.RootCAs = certPool
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// KillProcessOnPort kills any process listening on the specified port
func KillProcessOnPort(t *testing.T, port string) {
	cmd := exec.Command("lsof", "-ti:"+port)
	output, err := cmd.Output()
	if err != nil {
		// No process found on this port, which is fine
		return
	}

	pids := strings.TrimSpace(string(output))
	if pids == "" {
		return
	}

	for _, pid := range strings.Split(pids, "\n") {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}

		t.Logf("Killing process %s on port %s", pid, port)
		killCmd := exec.Command("kill", "-TERM", pid)
		_ = killCmd.Run() // Ignore error, process might already be dead

		// Wait a bit for graceful shutdown
		time.Sleep(500 * time.Millisecond)

		// Check if still running
		checkCmd := exec.Command("kill", "-0", pid)
		if checkCmd.Run() == nil {
			// Process still running, force kill
			t.Logf("Force killing process %s on port %s", pid, port)
			forceKillCmd := exec.Command("kill", "-9", pid)
			_ = forceKillCmd.Run()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// UseFakeEnclave reports whether the test harness should provision fake enclaves
// instead of real Nitro enclaves. An explicit ENCLAVE_TYPE=FAKE always selects
// fake. Otherwise, when ENCLAVE_TYPE is unset and nitro-cli is not installed,
// the harness falls back to fake so tests run on non-Nitro machines without the
// caller needing to set anything — except when REMOTE_ENCLAVE_URLS points the
// run at remote real enclaves.
func UseFakeEnclave() bool {
	if os.Getenv(types.EnvEnclaveType) == string(types.EnclaveTypeFake) {
		return true
	}
	if os.Getenv("REMOTE_ENCLAVE_URLS") != "" {
		return false
	}
	if _, pinned := os.LookupEnv(types.EnvEnclaveType); !pinned {
		if _, err := exec.LookPath("nitro-cli"); err != nil {
			return true
		}
	}
	return false
}

func MustSetupEnclave(t *testing.T, rootDir string, enclaveCID string, httpPort string, configHttpPort string, app string, enclaveName string, isFirstEnclave bool) func() {
	scriptName := "build-and-run-go-enclave.sh"
	scriptDir := "nitro"
	if UseFakeEnclave() {
		scriptName = "build-and-run-fake-enclave.sh"
		scriptDir = "fake"
	}
	buildAndRunPath := filepath.Join(rootDir, "enclave", scriptDir, scriptName)
	if _, err := os.Stat(buildAndRunPath); os.IsNotExist(err) {
		t.Fatalf("%s script not found at: %s", scriptName, buildAndRunPath)
	}

	// Delete stale EIF to force a fresh build. Cached EIFs from previous
	// runs may contain old app binaries, causing hard-to-debug failures.
	staleEIF := filepath.Join(rootDir, "enclave", "apps", app, "go-enclave-outbound-cid"+enclaveCID+".eif")
	if err := os.Remove(staleEIF); err == nil {
		t.Logf("Removed stale EIF: %s", staleEIF)
	}

	// Kill any existing processes on the target ports before starting
	t.Logf("Checking for existing processes on ports %s and %s...", httpPort, configHttpPort)
	KillProcessOnPort(t, httpPort)
	KillProcessOnPort(t, configHttpPort)

	// Set up a cleanup handler to kill the enclave process.
	var enclaveCmd *exec.Cmd
	cleanup := func() {
		// First, kill the enclave process
		if enclaveCmd != nil && enclaveCmd.Process != nil {
			t.Log("Terminating enclave process...")
			_ = enclaveCmd.Process.Signal(os.Interrupt) // Try graceful shutdown first

			// Wait a bit for graceful shutdown
			time.Sleep(500 * time.Millisecond)

			// Then force kill if needed
			_ = enclaveCmd.Process.Kill()

			// Wait for process to exit, but don't treat expected signals as errors
			if err := enclaveCmd.Wait(); err != nil {
				// These errors are expected when we kill the process
				errStr := err.Error()
				if errStr != "signal: killed" && errStr != "signal: terminated" &&
					errStr != "signal: interrupt" && errStr != "context canceled" {
					t.Logf("Unexpected error waiting for enclave process: %v", err)
				}
			}
		}

		// Terminate the specific enclave by name (only if using real nitro environment)
		if !UseFakeEnclave() {
			t.Logf("Terminating enclave '%s' via nitro-cli...", enclaveName)
			cleanupCmd := exec.Command("nitro-cli", "terminate-enclave", "--enclave-name", enclaveName)
			cleanupOutput, err := cleanupCmd.CombinedOutput()
			if err != nil {
				t.Logf("Failed to terminate enclave '%s': %v, output: %s", enclaveName, err, string(cleanupOutput))
			} else {
				t.Logf("Enclave '%s' terminated successfully", enclaveName)
			}
		}

		// Give the bash script and host-server time to clean up
		// The script should handle killing the host-server when it exits
		time.Sleep(1 * time.Second)
	}

	t.Logf("Starting enclave '%s' with CID %s on ports %s/%s...", enclaveName, enclaveCID, httpPort, configHttpPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var enclaveOutput bytes.Buffer
	outputMutex := &sync.Mutex{}
	enclaveDone := make(chan struct{})
	enclaveReady := make(chan struct{})
	defer close(enclaveDone)
	enclaveCmd = exec.CommandContext(ctx, buildAndRunPath)
	enclaveCmd.Dir = rootDir

	// Build environment variables
	envVars := []string{
		fmt.Sprintf("%s=%s", types.EnvEnclaveCID, enclaveCID),
		fmt.Sprintf("HTTP_PORT=%s", httpPort),
		fmt.Sprintf("CONFIG_HTTP_PORT=%s", configHttpPort),
		fmt.Sprintf("APP=%s", app),
		fmt.Sprintf("ENCLAVE_NAME=%s", enclaveName),
		"KEYPAIR_ROTATION=15s",
		"KEYPAIR_EXPIRATION=10m",
		// Let tests re-POST /config to exercise reconfiguration (e.g. zeroing an
		// enclave's config and restoring it).
		"ALLOW_RECONFIG=true",
	}

	// For subsequent enclaves, skip allocator restart and image rebuilding
	if !isFirstEnclave {
		envVars = append(envVars, "SKIP_ALLOCATOR_RESTART=true", "SKIP_IMAGE_BUILD=true")
	}

	enclaveCmd.Env = append(os.Environ(), envVars...)
	enclaveOut, err := enclaveCmd.StdoutPipe()
	require.NoError(t, err)
	enclaveErr, err := enclaveCmd.StderrPipe()
	require.NoError(t, err)
	err = enclaveCmd.Start()
	require.NoError(t, err, "Failed to start enclave process")

	// Monitor enclave stdout for readiness.
	go func() {
		scanner := bufio.NewScanner(enclaveOut)
		for scanner.Scan() {
			line := scanner.Text()
			outputMutex.Lock()
			enclaveOutput.WriteString(line + "\n")
			outputMutex.Unlock()

			if strings.Contains(line, "API endpoints available at") {
				select {
				case <-enclaveReady:
				default:
					close(enclaveReady)
				}
			}

			t.Logf("[Enclave setup]: %s", line)
		}
	}()

	// Monitor enclave errors (docker build writes progress/errors here).
	go func() {
		scanner := bufio.NewScanner(enclaveErr)
		for scanner.Scan() {
			line := scanner.Text()
			outputMutex.Lock()
			enclaveOutput.WriteString("enclave error: " + line + "\n")
			outputMutex.Unlock()
			t.Logf("[Enclave setup stderr]: %s", line)
		}
	}()

	t.Log("Waiting for enclave to be ready...")
	// The startup includes a Docker image build of the enclave Dockerfile
	// (CGO/wasmtime for confidential-workflows, go mod download for all apps),
	// which on a cold runner cache can run well past 15 minutes after a
	// chainlink-common dep bump pulls in many transitive packages.
	select {
	case <-enclaveReady:
		t.Log("Enclave is ready!")
	case <-time.After(60 * time.Minute):
		t.Fatal("Timeout waiting for enclave to start")
	}
	time.Sleep(10 * time.Second)

	return cleanup
}

// enclaveDescribeEntry represents the JSON output of `nitro-cli describe-enclaves`.
type enclaveDescribeEntry struct {
	EnclaveCID   int        `json:"EnclaveCID"`
	Measurements nitro.PCRs `json:"Measurements"`
}

func EnsureEnclaveAndGetMeasurements(enclaveCID int) ([]byte, error) {
	if UseFakeEnclave() {
		return []byte(types.FakeMeasurements), nil
	}

	cmd := exec.Command("nitro-cli", "describe-enclaves")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run nitro-cli describe-enclaves: %w", err)
	}

	var entries []enclaveDescribeEntry
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse nitro-cli output: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no running enclaves found")
	}

	for _, entry := range entries {
		if entry.EnclaveCID == enclaveCID {
			measurementsBytes, err := json.Marshal(entry.Measurements)
			if err != nil {
				return nil, err
			}
			return measurementsBytes, nil
		}
	}

	var availableCIDs []int
	for _, entry := range entries {
		availableCIDs = append(availableCIDs, entry.EnclaveCID)
	}
	return nil, fmt.Errorf("enclave with CID %d not found, available CIDs: %v", enclaveCID, availableCIDs)
}
