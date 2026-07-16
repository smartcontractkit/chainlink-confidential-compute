package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	enclavetypes "github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-http/types"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var (
	enclaveCID     = "16"
	httpPort       = "8080"
	configHttpPort = "8081"

	enclaveURLEnvar = "REMOTE_ENCLAVE_URL"
	certEnvar       = "CA_CERT_PATH"
)

// SetupEnclaveApp starts an enclave running the named app. The environment
// (fake local processes vs. real AWS Nitro) is selected by UseFakeEnclave,
// which reads the ENCLAVE_TYPE environment variable. If a remote enclave URL is
// provided, it skips starting a local enclave.
func SetupEnclaveApp(
	t *testing.T,
	appName string,
) (cleanup func()) {
	if _, ok := os.LookupEnv(enclaveURLEnvar); !ok {
		warnIfFakeFallback(t)
		rootDir := findProjectRoot(t)
		cleanup := MustSetupEnclave(t, rootDir, enclaveCID, httpPort, configHttpPort, appName, fmt.Sprintf("%s-enclave", appName), true)
		return cleanup
	}
	return func() {}
}

// warnIfFakeFallback logs a warning when the harness runs against a fake enclave
// only because nitro-cli is unavailable, as opposed to fake being explicitly
// requested via ENCLAVE_TYPE=FAKE. Real Nitro is used automatically when the CLI
// is present.
func warnIfFakeFallback(t *testing.T) {
	explicitlyFake := os.Getenv(types.EnvEnclaveType) == string(types.EnclaveTypeFake)
	if UseFakeEnclave() && !explicitlyFake {
		t.Logf("nitro-cli not found; running against a FAKE enclave. Install nitro-cli to run on real hardware, or set %s=%s to silence this warning.", types.EnvEnclaveType, types.EnclaveTypeFake)
	}
}

// EnclaveExecution configures a single end-to-end request against an enclave
// app run by ExecuteEnclaveAppE2E. It is app-agnostic: callers supply the app
// identity, the request payload, the secrets to inject, and the threshold
// parameters. The enclave environment (fake vs. real Nitro) is selected
// globally by UseFakeEnclave.
type EnclaveExecution struct {
	// AppName is the directory under enclave/apps, used to locate the app's
	// measurements and build.
	AppName string
	// AppID is the versioned application identifier sent in the signed request.
	AppID string
	// Version is the application version sent in the signed request. Defaults to
	// "1.0.0" when empty.
	Version string

	PublicData  []byte
	Secrets     [][]byte
	SecretNames []string

	Threshold      int
	FaultTolerance int
	NumParties     int
}

// ExecuteEnclaveAppE2E runs an automated end-to-end test against an enclave app:
// 1. Run the set-config command
// 2. Run the fetch-public-keys command
// 3. Run the execute-batch command
// 4. Execute the request and return the result.
func ExecuteEnclaveAppE2E(
	t *testing.T,
	spec EnclaveExecution,
) (*types.ExecuteResponse, error) {
	appName := spec.AppName
	appID := spec.AppID
	version := spec.Version
	if version == "" {
		version = "1.0.0"
	}
	publicData := spec.PublicData
	secrets := spec.Secrets
	secretNames := spec.SecretNames
	threshold, faultTolerance, numParties := spec.Threshold, spec.FaultTolerance, spec.NumParties

	// Allow for testing remote enclaves locally, if a URL is provided.
	httpClient := http.DefaultClient
	rootDir := findProjectRoot(t)
	hostURL := fmt.Sprintf("http://localhost:%s", httpPort)
	configHostURL := fmt.Sprintf("http://localhost:%s", configHttpPort)
	remoteEnclaveURLStr, remoteEnclaveURLSet := os.LookupEnv(enclaveURLEnvar)
	if remoteEnclaveURLSet {
		hostURL = remoteEnclaveURLStr
		configHostURL = remoteEnclaveURLStr

		certPath, certPathSet := os.LookupEnv(certEnvar)
		if certPathSet {
			var err error
			httpClient, err = getHTTPClient(certPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create HTTP client with custom CA cert: %w", err)
			}
		}
	}

	// Load in the PCR measurements for the app. Fake enclaves produce no real
	// measurements (fake.ValidateAttestation ignores them), so use the canonical
	// fake placeholder instead of reading a pcr_measurements.json that won't exist.
	measurements := []byte(types.FakeMeasurements)
	if !UseFakeEnclave() {
		measurementsFilePath := filepath.Join(rootDir, "enclave", "apps", appName, "pcr_measurements.json")
		if _, statErr := os.Stat(measurementsFilePath); statErr == nil {
			var err error
			measurements, err = getMeasurements(measurementsFilePath)
			if err != nil {
				return nil, fmt.Errorf("failed to get enclave measurements: %w", err)
			}
		} else {
			// Reference apps (e.g. confidential-echo) publish no pinned
			// measurements. Fall back to the live measurements of the running
			// enclave so the flow still validates against real hardware.
			t.Logf("no %s; using live enclave measurements from nitro-cli", measurementsFilePath)
			cid, convErr := strconv.Atoi(enclaveCID)
			if convErr != nil {
				return nil, fmt.Errorf("invalid enclave CID %q: %w", enclaveCID, convErr)
			}
			liveMeasurements, liveErr := EnsureEnclaveAndGetMeasurements(cid)
			if liveErr != nil {
				return nil, fmt.Errorf("failed to get live enclave measurements: %w", liveErr)
			}
			measurements = liveMeasurements
		}
	}

	nodes := getNodes(hostURL, measurements)
	configNodes := getNodes(configHostURL, measurements)

	requestIDBytes := make([]byte, 32)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}
	var reqID [32]byte
	copy(reqID[:], requestIDBytes)

	// Generate enough signing keys to reach byzantine quorum (2*F+1)
	signingKeyStorage := mustGenerateEd25519Keys(t, 2*faultTolerance+1)
	tdh2KeyStorage := mustGenerateTDH2Keys(t, threshold, numParties)

	config := types.EnclaveConfig{
		Signers:         signingKeyStorage.PublicKeys,
		MasterPublicKey: tdh2KeyStorage.MasterPublicKey,
		T:               uint32(threshold),
		F:               uint32(faultTolerance),
	}
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	// Set config for all enclaves.
	for _, node := range configNodes {
		req := types.ConfigRequest{
			Config: configBytes,
		}
		resp, err := util.SetNodeConfig(context.Background(), node, req, httpClient)
		require.NoError(t, err)
		require.Equal(t, config, resp.Config)
	}

	enclavePool, err := newTestEnclavePool(nodes, httpClient)
	require.NoError(t, err)

	pubKeyResp, err := enclavePool.GetPublicKeys(t.Context(), reqID, nil)
	require.NoError(t, err)
	require.Len(t, pubKeyResp, len(nodes))
	enclaveKeys := mustGetEnclavePublicKeys(t, pubKeyResp)

	var enclaveIDs [][32]byte
	for _, enclaveNode := range nodes {
		enclaveIDs = append(enclaveIDs, enclaveNode.EnclaveID)
	}
	var masterPubKey tdh2easy.PublicKey
	require.NoError(t, masterPubKey.Unmarshal(tdh2KeyStorage.MasterPublicKey))
	ciphertexts, err := encryptUserSecrets(secrets, &masterPubKey)
	require.NoError(t, err)
	allResponses, err := prepareAndExecuteSignedRequests(
		context.Background(), nodes, enclaveIDs, reqID, publicData, ciphertexts, secretNames,
		&tdh2KeyStorage, &signingKeyStorage, enclaveKeys, httpClient, appID, version,
	)
	require.NoError(t, err)

	execResp, err := validateAndCoalesceResponses(allResponses, len(signingKeyStorage.PublicKeys), len(nodes))
	require.NoError(t, err)

	return execResp, nil
}

// TestConfigTrackerForNitroEnclaveE2E runs an automated end-to-end test of the config tracker
// This test will:
// 1. Start the enclave using build-and-run-go-enclave.sh.
// 2. Verify initial configuration is empty.
// 3. Start the config tracker with Sepolia network configuration.
// 4. Verify the enclave configuration is automatically updated with DON peer IDs.
func TestConfigTrackerForNitroEnclaveE2E(t *testing.T) {
	// Use a CapabilitiesRegistry deployment on a local simulated blockchain to fetch our DON info.
	donID := "1"
	expectedPeerIDs := []string{
		"09ca39cd924653c72fbb0e458b629c3efebdad3e29e7cd0b5760754d919ed829",
		"147d5cc651819b093cd2fdff9760f0f0f77b7ef7798d9e24fc6a350b7300e5d9",
		"2934f31f278e5c60618f85861bd6add54a4525d79a642019bdc87d75d26372c3",
		"298834a041a056df58c839cb53d99b78558693042e54dff238f504f16d18d4b6",
		"5f247f61a6d5bfdd1d5064db0bd25fe443648133c6131975edb23481424e3d9c",
		"77224be9d052343b1d17156a1e463625c0d746468d4f5a44cddd452365b1d4ed",
		"adb6bf005cdb23f21e11b82d66b9f62628c2939640ed93028bf0dad3923c5a8b",
		"b96933429b1a81c811e1195389d7733e936b03e8086e75ea1fa92c61564b6c31",
		"d7e9f2252b09edf0802a65b60bc9956691747894cb3ab9fefd072adf742eb9f1",
		"e38c9f2760db006f070e9cc1bc1c2269ad033751adaa85d022fb760cbc5b5ef6",
	}
	f := uint32(1)
	threshold := uint32(1)
	masterPublicKey := hex.EncodeToString([]byte("test-public-key"))
	capabilitiesRegistryAddr := setupLocalCapabilitiesRegistry(t, expectedPeerIDs, f)

	warnIfFakeFallback(t)

	rootDir := findProjectRoot(t)
	cleanup := MustSetupEnclave(t, rootDir, enclaveCID, httpPort, configHttpPort, "confidential-http", fmt.Sprintf("%s-enclave", "confidential-http"), true)
	defer cleanup()

	t.Logf("Testing WS RPC at %s", localRPCWS)
	wsClient, err := ethclient.Dial(localRPCWS)
	require.NoError(t, err)
	defer wsClient.Close()
	wsChainID, err := wsClient.ChainID(context.Background())
	require.NoError(t, err)
	require.Equal(t, simulatedChainID, wsChainID)
	t.Logf("WebSocket RPC connection successful, chain ID: %s", wsChainID.String())

	t.Logf("Testing HTTP RPC at %s", localRPCHTTP)
	httpClient, err := ethclient.Dial(localRPCHTTP)
	require.NoError(t, err)
	defer httpClient.Close()
	httpChainID, err := httpClient.ChainID(context.Background())
	require.NoError(t, err)
	require.Equal(t, simulatedChainID, httpChainID)
	t.Logf("HTTP RPC connection successful, chain ID: %s", httpChainID.String())

	t.Log("Checking initial enclave configuration...")
	hostURL := fmt.Sprintf("http://localhost:%s", httpPort)
	initialConfigCmd := exec.Command("curl", "-s", hostURL+"/publicKeys")
	initialConfigOutput, err := initialConfigCmd.CombinedOutput()
	require.NoError(t, err, "Failed to fetch initial config: %s", string(initialConfigOutput))
	t.Logf("Initial config response: %s", string(initialConfigOutput))

	t.Log("Starting config tracker...")
	configTrackerCtx, configTrackerCancel := context.WithCancel(context.Background())
	defer configTrackerCancel()
	nodeConfigJSON := fmt.Sprintf(`[{"name":"sepolia-node","wsURL":"%s","httpURL":"%s"}]`, localRPCWS, localRPCHTTP)
	configTrackerDir := filepath.Join(rootDir, "enclave", "config-tracker")
	configTrackerCmd := exec.CommandContext(configTrackerCtx, "go", "run", ".")
	configTrackerCmd.Dir = configTrackerDir
	configTrackerCmd.Env = append(os.Environ(),
		fmt.Sprintf("CAP_REG_ADDR=%s", capabilitiesRegistryAddr),
		fmt.Sprintf("CHAIN_ID=%s", simulatedChainID.String()),
		fmt.Sprintf("DON_ID=%s", donID),
		fmt.Sprintf("INITIAL_T=%d", threshold),
		fmt.Sprintf("INITIAL_MASTER_PUBLIC_KEY=%s", masterPublicKey),
		fmt.Sprintf("HOST_PORT=%s", httpPort),
		fmt.Sprintf("CONFIG_PORT=%s", configHttpPort),
		fmt.Sprintf("NODE_CONFIG=%s", nodeConfigJSON),
	)

	var configTrackerOutput bytes.Buffer
	configTrackerOut, err := configTrackerCmd.StdoutPipe()
	require.NoError(t, err)
	configTrackerErr, err := configTrackerCmd.StderrPipe()
	require.NoError(t, err)
	err = configTrackerCmd.Start()
	require.NoError(t, err, "Failed to start config tracker")

	// Set up cleanup for config tracker
	defer func() {
		if configTrackerCmd.Process != nil {
			t.Log("Terminating config tracker process...")
			err := configTrackerCmd.Process.Kill()
			if err != nil {
				t.Logf("Failed to kill config tracker process: %v", err)
			}
		}
	}()

	// Monitor config tracker output
	go func() {
		scanner := bufio.NewScanner(configTrackerOut)
		for scanner.Scan() {
			line := scanner.Text()
			configTrackerOutput.WriteString(line + "\n")
			t.Logf("[Config Tracker]: %s", line)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(configTrackerErr)
		for scanner.Scan() {
			line := scanner.Text()
			configTrackerOutput.WriteString("config tracker stderr: " + line + "\n")
			if strings.Contains(line, `"level":"error"`) {
				t.Logf("[Config Tracker Error]: %s", line)
			} else {
				t.Logf("[Config Tracker]: %s", line)
			}
		}
	}()

	t.Log("Waiting for config tracker to update enclave configuration...")

	// Convert expected peer IDs from hex to base64 for comparison
	expectedPeerIDsBase64 := make([]string, len(expectedPeerIDs))
	for i, hexPeerID := range expectedPeerIDs {
		peerBytes, err := hex.DecodeString(hexPeerID)
		require.NoError(t, err, "Failed to decode hex peer ID: %s", hexPeerID)
		expectedPeerIDsBase64[i] = util.EncodeToString(peerBytes)
	}

	// Poll for configuration updates.
	configUpdated := false
	maxWaitTime := 2 * time.Minute
	pollInterval := 5 * time.Second
	startTime := time.Now()
	for time.Since(startTime) < maxWaitTime {
		time.Sleep(pollInterval)

		// Check current configuration
		configCmd := exec.Command("curl", "-s", hostURL+"/publicKeys")
		configOutput, err := configCmd.CombinedOutput()
		if err != nil {
			t.Logf("Failed to fetch config during polling: %v", err)
			continue
		}

		configStr := string(configOutput)
		t.Logf("Current config: %s", configStr)

		// Check if configuration contains expected peer IDs (base64 encoded)
		foundPeerIDs := 0
		for i, peerIDBase64 := range expectedPeerIDsBase64 {
			if strings.Contains(configStr, peerIDBase64) {
				foundPeerIDs++
				t.Logf("Found peer ID %d (hex: %s, base64: %s)", i, expectedPeerIDs[i], peerIDBase64)
			}
		}

		if foundPeerIDs >= len(expectedPeerIDsBase64)/2 { // At least half the peer IDs should be present
			configUpdated = true
			t.Logf("Configuration updated successfully! Found %d/%d expected peer IDs", foundPeerIDs, len(expectedPeerIDsBase64))
			break
		}

		t.Logf("Config not yet updated, found %d/%d expected peer IDs. Waiting...", foundPeerIDs, len(expectedPeerIDsBase64))
	}

	require.True(t, configUpdated, "Config tracker did not update the enclave configuration within the timeout period")

	// Final verification - get the final configuration
	finalConfigCmd := exec.Command("curl", "-s", hostURL+"/publicKeys")
	finalConfigOutput, err := finalConfigCmd.CombinedOutput()
	require.NoError(t, err, "Failed to fetch final config: %s", string(finalConfigOutput))

	finalConfigStr := string(finalConfigOutput)
	t.Logf("Final enclave configuration: %s", finalConfigStr)

	var pubKeyResponse types.PublicKeyResponse
	err = json.Unmarshal(finalConfigOutput, &pubKeyResponse)
	require.NoError(t, err, "Failed to unmarshal final config response")
	t.Logf("Final enclave config - Signers count: %d, PublicKey: %s, T: %d, F: %d",
		len(pubKeyResponse.Config.Signers), pubKeyResponse.Config.MasterPublicKey,
		pubKeyResponse.Config.T, pubKeyResponse.Config.F,
	)
	assert.Equal(t, threshold, pubKeyResponse.Config.T)
	assert.Equal(t, []byte("test-public-key"), pubKeyResponse.Config.MasterPublicKey)
	assert.Equal(t, f, pubKeyResponse.Config.F)

	// Verify that the configuration contains signers (peer IDs)
	assert.Contains(t, finalConfigStr, "signers", "Final configuration should contain signers")
	assert.Contains(t, finalConfigStr, "publicKey", "Final configuration should contain publicKey")

	// Verify at least some of the expected peer IDs are present
	foundPeerIDs := 0
	for i, peerIDBase64 := range expectedPeerIDsBase64 {
		if strings.Contains(finalConfigStr, peerIDBase64) {
			foundPeerIDs++
			t.Logf("Final verification: Found peer ID %d (hex: %s, base64: %s)", i, expectedPeerIDs[i], peerIDBase64)
		}
	}
	assert.Equal(t, foundPeerIDs, len(expectedPeerIDs))

	t.Log("Config tracker E2E test completed successfully!")
}

// TestConfidentialEchoEnclave exercises the reference confidential-echo app
// end-to-end: it injects secrets, renders the public input template inside the
// enclave, and checks the returned output. It runs against a real Nitro enclave
// when nitro-cli is available and falls back to a fake enclave otherwise. The
// app publishes no pinned PCR measurements, so the harness uses the running
// enclave's live measurements under real Nitro.
func TestConfidentialEchoEnclave(t *testing.T) {
	enclaveAppName := "confidential-echo"
	cleanup := SetupEnclaveApp(t, enclaveAppName)
	defer cleanup()

	testCases := []struct {
		name           string
		threshold      int
		numParties     int
		faultTolerance int
		publicData     string
		secrets        [][]byte
		secretNames    []string
		expectedOutput string
	}{
		{
			name:           "single secret",
			threshold:      2,
			numParties:     3,
			faultTolerance: 1,
			publicData:     "hello {{.name}}",
			secrets:        [][]byte{[]byte("Alice")},
			secretNames:    []string{"name"},
			expectedOutput: "hello Alice",
		},
		{
			name:           "multiple secrets",
			threshold:      3,
			numParties:     5,
			faultTolerance: 2,
			publicData:     "{{.greeting}}, {{.name}}!",
			secrets:        [][]byte{[]byte("hi"), []byte("Bob")},
			secretNames:    []string{"greeting", "name"},
			expectedOutput: "hi, Bob!",
		},
	}

	for i := range testCases {
		tc := &testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ExecuteEnclaveAppE2E(t, EnclaveExecution{
				AppName:        enclaveAppName,
				AppID:          types.AppIDConfidentialEcho,
				PublicData:     []byte(tc.publicData),
				Secrets:        tc.secrets,
				SecretNames:    tc.secretNames,
				Threshold:      tc.threshold,
				FaultTolerance: tc.faultTolerance,
				NumParties:     tc.numParties,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, string(resp.Output))
		})
	}
}

func TestConfidentialHttpEnclave(t *testing.T) {
	enclaveAppName := "confidential-http"
	cleanup := SetupEnclaveApp(t, enclaveAppName)
	defer cleanup()

	// If postman-echo is down, fall back to a local server.
	echoServerURL := types.PostmanEchoURL
	client := &http.Client{Timeout: 10 * time.Second}
	_, err := client.Get(echoServerURL)
	if err != nil {
		echoServerURL = strings.ReplaceAll(util.StartEchoServer(8082), "localhost", "10.0.0.3")
	}

	thresholdTestCases := []struct {
		name                    string
		threshold               int
		numParties              int
		faultTolerance          int
		publicData              enclavetypes.Request
		secrets                 [][]byte
		secretNames             []string
		expectedResponseStrings []string
	}{
		{
			name:           "standard post request",
			threshold:      2,
			numParties:     3,
			faultTolerance: 1,
			publicData: enclavetypes.Request{
				Url:  echoServerURL + "post",
				Body: &enclavetypes.Request_BodyString{BodyString: `{"name": "{{.name}}", "action": "{{.action}}", "cc": "{{.cc}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.apiKey}}"}},
					"X-User-Name":   {Values: []string{"{{.username}}"}},
				},
				Method: http.MethodPost,
				TemplatePublicValues: map[string]string{
					"action": "test",
				},
			},
			secrets: [][]byte{ // corresponds to `TemplateCiphertextNames`
				[]byte("John Smith"),
				[]byte("1111-2222-3333-4444"),
				[]byte("API-KEY-123"),
				[]byte("@johnsmith"),
			},
			secretNames: []string{"name", "cc", "apiKey", "username"}, // corresponds to `secrets`
			expectedResponseStrings: []string{ // we don't check the exact response, but look for key strings
				`"name":"John Smith"`,
				`"action":"test"`,
				`"cc":"1111-2222-3333-4444"`,
				fmt.Sprintf(`"url":"%spost"`, echoServerURL),
				`"authorization":"Bearer API-KEY-123"`,
				`"x-user-name":"@johnsmith"`,
			},
		},
		{
			name:           "get request with query params",
			threshold:      3,
			numParties:     5,
			faultTolerance: 2,
			publicData: enclavetypes.Request{
				Url:    echoServerURL + "get?param1=value1",
				Method: http.MethodGet,
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.apiKey}}"}},
				},
				TemplatePublicValues: map[string]string{
					"request_type": "user_info",
				},
			},
			secrets:     [][]byte{[]byte("API-KEY-123")},
			secretNames: []string{"apiKey"},
			expectedResponseStrings: []string{
				`"param1":"value1"`,
				`"authorization":"Bearer API-KEY-123"`,
				`"url":"` + echoServerURL + `get?param1=value1"`,
			},
		},
		{
			name:           "post request with json body",
			threshold:      3,
			numParties:     5,
			faultTolerance: 2,
			publicData: enclavetypes.Request{
				Url:    echoServerURL + "post",
				Method: http.MethodPost,
				Body:   &enclavetypes.Request_BodyString{BodyString: `{"name": "{{.name}}", "action": "{{.action}}", "cc": "{{.cc}}"}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.apiKey}}"}},
					"Content-Type":  {Values: []string{"application/json"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "update_profile",
				},
			},
			secrets: [][]byte{
				[]byte("John Smith"),
				[]byte("1111-2222-3333-4444"),
				[]byte("API-KEY-123"),
			},
			secretNames: []string{"name", "cc", "apiKey"},
			expectedResponseStrings: []string{
				`"name":"John Smith"`,
				`"action":"update_profile"`,
				`"cc":"1111-2222-3333-4444"`,
				`"authorization":"Bearer API-KEY-123"`,
				`"url":"` + echoServerURL + `post"`,
			},
		},
		{
			name:           "put request with form data",
			threshold:      3,
			numParties:     5,
			faultTolerance: 2,
			publicData: enclavetypes.Request{
				Url:    echoServerURL + "put",
				Method: http.MethodPut,
				Body:   &enclavetypes.Request_BodyString{BodyString: `username={{.username}}&password={{.password}}`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Authorization": {Values: []string{"Bearer {{.apiKey}}"}},
					"Content-Type":  {Values: []string{"application/x-www-form-urlencoded"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "change_credentials",
				},
			},
			secrets: [][]byte{
				[]byte("API-KEY-123"),
				[]byte("@johnsmith"),
				[]byte("secure123"),
			},
			secretNames: []string{"apiKey", "username", "password"},
			expectedResponseStrings: []string{
				`"username":"@johnsmith"`,
				`"password":"secure123"`,
				`"authorization":"Bearer API-KEY-123"`,
				`"url":"` + echoServerURL + `put"`,
			},
		},
		{
			name:           "trivial case no secrets",
			threshold:      1,
			numParties:     1,
			faultTolerance: 0,
			publicData: enclavetypes.Request{
				Url:    echoServerURL + "post",
				Method: http.MethodPost,
				Body:   &enclavetypes.Request_BodyString{BodyString: `<request><action>{{.action}}</action></request>`},
				MultiHeaders: map[string]*enclavetypes.HeaderValues{
					"Content-Type": {Values: []string{"application/xml"}},
				},
				TemplatePublicValues: map[string]string{
					"action": "finish",
				},
			},
			expectedResponseStrings: []string{
				`<request><action>finish</action></request>`,
				`"url":"` + echoServerURL + `post"`,
			},
		},
	}

	for i := range thresholdTestCases {
		tc := &thresholdTestCases[i]
		t.Run(tc.name, func(t *testing.T) {
			publicDataBytes, err := proto.Marshal(&tc.publicData)
			require.NoError(t, err)

			// Run the request through the enclave app, and validate the response.
			resp, err := ExecuteEnclaveAppE2E(t, EnclaveExecution{
				AppName:        enclaveAppName,
				AppID:          types.AppIDConfidentialHTTP,
				PublicData:     publicDataBytes,
				Secrets:        tc.secrets,
				SecretNames:    tc.secretNames,
				Threshold:      tc.threshold,
				FaultTolerance: tc.faultTolerance,
				NumParties:     tc.numParties,
			})
			require.NoError(t, err)
			var response enclavetypes.Response
			require.NoError(t, proto.Unmarshal(resp.Output, &response))
			for _, expected := range tc.expectedResponseStrings {
				assert.Contains(t, string(response.Body), expected)
			}
		})
	}
}
