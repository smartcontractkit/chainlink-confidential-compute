package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/workflow/generated/capabilities_registry_wrapper_v2"
	evmClient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

const (
	localhostPrefix = "http://localhost"
	refreshInterval = 1 * time.Minute
)

// Information for these settings can be seen here: https://github.com/smartcontractkit/chainlink/blob/develop/core/config/docs/chains-evm.toml#L1-L4
var (
	chainTypeStr                  = ""
	finalityDepth                 = util.Ptr(uint32(10))
	finalityTagEnabled            = util.Ptr(true)
	noNewHeadsThreshold           = time.Second * 60
	finalizedBlockOffset          = util.Ptr[uint32](16)
	noNewFinalizedBlocksThreshold = time.Second * 60
)

// Information for these settings can be seen here: https://github.com/smartcontractkit/chainlink/blob/develop/core/config/docs/chains-evm.toml#L409-L412
var (
	selectionMode         = util.Ptr("HighestHead")
	leaseDuration         = 5 * time.Minute
	pollFailureThreshold  = util.Ptr(uint32(5))
	pollInterval          = 10 * time.Second
	syncThreshold         = util.Ptr(uint32(5))
	nodeIsSyncingEnabled  = util.Ptr(false)
	enforceRepeatableRead = util.Ptr(true)
	deathDeclarationDelay = time.Second * 3
	confirmationTimeout   = time.Second * 60
	newHeadsPollInterval  = 0 * time.Second
)

func main() {
	lggr, err := logger.New()
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}

	lggr.Info("Fetching configuration from environment...")
	capRegAddr, chainID, donID, hostPort, configPort, nodeConfig, initialMasterPublicKey, initialT, requireBFTQuorum, err := loadConfigFromEnv()
	if err != nil {
		lggr.Fatalf("Failed to load config from env: %v", err)
	}

	lggr.Info("Creating EVM client...")
	chainCfg, nodePool, nodes, err := evmClient.NewClientConfigs(selectionMode, leaseDuration, chainTypeStr, nodeConfig,
		pollFailureThreshold, pollInterval, syncThreshold, nodeIsSyncingEnabled, noNewHeadsThreshold, finalityDepth,
		finalityTagEnabled, finalizedBlockOffset, enforceRepeatableRead, deathDeclarationDelay, noNewFinalizedBlocksThreshold,
		pollInterval, newHeadsPollInterval, confirmationTimeout, finalityDepth)
	if err != nil {
		lggr.Fatalf("Failed to create client configs: %v", err)
	}
	client, err := evmClient.NewEvmClient(nodePool, chainCfg, nil, lggr, chainID, nodes, chaintype.ChainType(chainTypeStr))
	if err != nil {
		lggr.Fatalf("Failed to create EVM client: %v", err)
	}
	err = client.Dial(context.Background())
	if err != nil {
		lggr.Fatalf("Failed to dial EVM client: %v", err)
	}
	lggr.Infof("EVM client created successfully")

	lggr.Infof("Creating capabilities registry client for address: %s", capRegAddr.Hex())
	reg, err := capabilities_registry_wrapper_v2.NewCapabilitiesRegistry(capRegAddr, client)
	if err != nil {
		lggr.Fatalf("Failed to create capabilities registry: %v", err)
	}
	lggr.Infof("Capabilities registry client created successfully")

	configTracker := NewConfigTracker(reg, lggr, donID, hostPort, configPort, time.Minute, initialT, initialMasterPublicKey, requireBFTQuorum)
	configTracker.Start()
}

func loadConfigFromEnv() (common.Address, *big.Int, uint32, string, string, []evmClient.NodeConfig, []byte, uint32, bool, error) {
	capRegAddrStr := os.Getenv("CAP_REG_ADDR")
	if capRegAddrStr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("CAP_REG_ADDR environment variable is required")
	}
	capRegAddr := common.HexToAddress(capRegAddrStr)

	chainIDStr := os.Getenv("CHAIN_ID")
	if chainIDStr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("CHAIN_ID environment variable is required")
	}
	chainID, ok := new(big.Int).SetString(chainIDStr, 10)
	if !ok {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("failed to parse CHAIN_ID: %s", chainIDStr)
	}

	donIDStr := os.Getenv("DON_ID")
	if donIDStr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("DON_ID environment variable is required")
	}
	parsed, err := strconv.ParseUint(donIDStr, 10, 32)
	if err != nil {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("failed to parse DON_ID: %w", err)
	}
	donID := uint32(parsed)

	hostPort := os.Getenv("HOST_PORT")
	if hostPort == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("HOST_PORT environment variable is required")
	}

	configPort := os.Getenv("CONFIG_PORT")
	if configPort == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("CONFIG_PORT environment variable is required")
	}

	nodeConfigStr := os.Getenv("NODE_CONFIG")
	if nodeConfigStr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("NODE_CONFIG environment variable is required")
	}
	var nodeConfig []evmClient.NodeConfig
	if err := json.Unmarshal([]byte(nodeConfigStr), &nodeConfig); err != nil {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("failed to parse NODE_CONFIG: %w", err)
	}

	masterPublicKeyStr := os.Getenv("INITIAL_MASTER_PUBLIC_KEY")
	if masterPublicKeyStr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("INITIAL_MASTER_PUBLIC_KEY environment variable is required")
	}
	masterPublicKey, err := hex.DecodeString(masterPublicKeyStr)
	if err != nil {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("failed to parse INITIAL_MASTER_PUBLIC_KEY: %w", err)
	}
	tstr := os.Getenv("INITIAL_T")
	if tstr == "" {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("INITIAL_T environment variable is required")
	}
	tval, err := strconv.ParseUint(tstr, 10, 32)
	if err != nil {
		return common.Address{}, nil, 0, "", "", nil, nil, 0, false, fmt.Errorf("failed to parse initial T: %w", err)
	}

	requireBFTQuorum := os.Getenv("REQUIRE_BFT_QUORUM") == "true"

	return capRegAddr, chainID, donID, hostPort, configPort, nodeConfig, masterPublicKey, uint32(tval), requireBFTQuorum, nil
}
