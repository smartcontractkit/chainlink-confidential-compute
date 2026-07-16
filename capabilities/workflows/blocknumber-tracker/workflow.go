package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"

	"workflows/contracts/evm/src/generated/reserve_manager"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/blockchain/evm"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/confidentialhttp"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/scheduler/cron"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// EVMConfig holds per-chain configuration.
type EVMConfig struct {
	ReserveManagerAddress string `json:"reserveManagerAddress"`
	ChainName             string `json:"chainName"`
	GasLimit              uint64 `json:"gasLimit"`
}

func (e *EVMConfig) GetChainSelector() (uint64, error) {
	return evm.ChainSelectorFromName(e.ChainName)
}

func (e *EVMConfig) NewEVMClient() (*evm.Client, error) {
	chainSelector, err := e.GetChainSelector()
	if err != nil {
		return nil, err
	}
	return &evm.Client{
		ChainSelector: chainSelector,
	}, nil
}

type Config struct {
	Schedule string      `json:"schedule"`
	URL      string      `json:"url"`
	EVMs     []EVMConfig `json:"evms"`
}

type blockNumberOutput struct {
	BlockNum *big.Int
}

func InitWorkflow(config *Config, logger *slog.Logger, secretsProvider cre.SecretsProvider) (cre.Workflow[*Config], error) {
	cronTriggerCfg := &cron.Config{
		Schedule: config.Schedule,
	}

	workflow := cre.Workflow[*Config]{
		cre.Handler(
			cron.Trigger(cronTriggerCfg),
			onPORCronTrigger,
		),
	}

	return workflow, nil
}

func onPORCronTrigger(config *Config, runtime cre.Runtime, outputs *cron.Payload) (string, error) {
	return doPOR(config, runtime)
}

func doPOR(config *Config, runtime cre.Runtime) (string, error) {
	logger := runtime.Logger()
	// Fetch PoR
	logger.Info("fetching por", "url", config.URL, "evms", config.EVMs)

	url := config.URL
	payload := `{"method":"{{.method}}","params":[],"id":1,"jsonrpc":"2.0"}`
	headers := map[string]*confidentialhttp.HeaderValues{
		"Content-Type":  {Values: []string{"application/json"}},
		"Authorization": {Values: []string{"Basic {{.infurasecret}}"}},
	}
	runtime.Logger().Info(
		"[Crosschain blocknumber workflow] Calling confidential HTTP capability",
		"url", url,
		"payload", payload,
		"headers", headers,
	)
	confHttpClient := confidentialhttp.Client{}
	confOutput, err := confHttpClient.SendRequest(runtime, &confidentialhttp.ConfidentialHTTPRequest{
		Request: &confidentialhttp.HTTPRequest{
			Url:           url,
			Method:        "POST",
			Body:          &confidentialhttp.HTTPRequest_BodyString{BodyString: payload},
			MultiHeaders:  headers,
			EncryptOutput: true,
		},
		VaultDonSecrets: []*confidentialhttp.SecretIdentifier{
			{
				Key: "method",
			},
			{
				Key: "san_marino_aes_gcm_encryption_key",
			},
			{
				Key: "infurasecret",
			},
		},
	}).Await()
	if err != nil {
		return "", fmt.Errorf("failed to get confidential HTTP response: %w", err)
	}

	// Do not do this in production code!
	// This tests the AES-GCM encryption and decryption functionality for confidential HTTP.
	testSymmetricKeyHex := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	keyBytes, err := hex.DecodeString(testSymmetricKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to hex-decode AES key: %w", err)
	}
	decryptedBody, err := AESGCMDecrypt(confOutput.Body, keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt confidential HTTP response: %w", err)
	}
	runtime.Logger().Info("[Crosschain blocknumber workflow] Decrypted confidential HTTP response", "decryptedResponse", string(decryptedBody))
	var httpOutput map[string]interface{}
	if err := json.Unmarshal(decryptedBody, &httpOutput); err != nil {
		return "", fmt.Errorf("failed to unmarshal HTTP response: %w, %s", err, string(decryptedBody))
	}
	result := httpOutput["result"].(string)
	resultNum, ok := big.NewInt(0).SetString(result[2:], 16)
	if !ok {
		return "", fmt.Errorf("failed to convert result to big.Int: %s", result)
	}
	runtime.Logger().Info("[Crosschain blocknumber workflow] Got block number", "response", resultNum.String())
	blockNumOut := blockNumberOutput{BlockNum: resultNum}

	// Update reserves
	if err := updateReserves(config, runtime, big.NewInt(0), blockNumOut.BlockNum); err != nil {
		return "", fmt.Errorf("failed to update reserves: %w", err)
	}

	return blockNumOut.BlockNum.String(), nil
}

func updateReserves(config *Config, runtime cre.Runtime, totalSupply *big.Int, totalReserveScaled *big.Int) error {
	evmCfg := config.EVMs[0]
	logger := runtime.Logger()
	logger.Info("Updating reserves", "totalSupply", totalSupply, "totalReserveScaled", totalReserveScaled)

	evmClient, err := evmCfg.NewEVMClient()
	if err != nil {
		return fmt.Errorf("failed to create EVM client for %s: %w", evmCfg.ChainName, err)
	}

	reserveManager, err := reserve_manager.NewReserveManager(evmClient, common.HexToAddress(evmCfg.ReserveManagerAddress), nil)
	if err != nil {
		return fmt.Errorf("failed to create reserve manager: %w", err)
	}

	logger.Info("Writing report", "totalSupply", totalSupply, "totalReserveScaled", totalReserveScaled)
	resp, err := reserveManager.WriteReportFromUpdateReserves(runtime, reserve_manager.UpdateReserves{
		TotalMinted:  totalSupply,
		TotalReserve: totalReserveScaled,
	}, nil).Await()

	if err != nil {
		logger.Error("WriteReport await failed", "error", err, "errorType", fmt.Sprintf("%T", err))
		return fmt.Errorf("failed to write report: %w", err)
	}
	logger.Info("Write report succeeded", "response", resp)
	logger.Info("Write report transaction succeeded at", "txHash", common.BytesToHash(resp.TxHash).Hex())
	return nil
}

// This is currently not used in our codebase, but provided for users who want to decrypt
// AES-GCM encrypted output from the enclave.
func AESGCMDecrypt(blob []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext+tag
	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
