package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var validConfigEnv = map[string]string{
	"CAP_REG_ADDR":              "0x76c9cf548b4179f8901cda1f8623568b58215e62",
	"CHAIN_ID":                  "1",
	"DON_ID":                    "7",
	"HOST_PORT":                 "8080",
	"CONFIG_PORT":               "8081",
	"NODE_CONFIG":               `[{"Name":"primary","WSURL":"wss://rpc.example","HTTPURL":"https://rpc.example"}]`,
	"INITIAL_MASTER_PUBLIC_KEY": "abcd",
	"INITIAL_T":                 "5",
	"REQUIRE_BFT_QUORUM":        "true",
}

func setConfigEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	for k, v := range validConfigEnv {
		t.Setenv(k, v)
	}
	for k, v := range overrides {
		t.Setenv(k, v)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	setConfigEnv(t, nil)
	capRegAddr, chainID, donID, hostPort, configPort, nodeConfig, masterPublicKey, initialT, requireBFTQuorum, err := loadConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, common.HexToAddress("0x76c9cf548b4179f8901cda1f8623568b58215e62"), capRegAddr)
	assert.Equal(t, big.NewInt(1), chainID)
	assert.Equal(t, uint32(7), donID)
	assert.Equal(t, "8080", hostPort)
	assert.Equal(t, "8081", configPort)
	require.Len(t, nodeConfig, 1)
	assert.Equal(t, "https://rpc.example", *nodeConfig[0].HTTPURL)
	assert.Equal(t, []byte{0xab, 0xcd}, masterPublicKey)
	assert.Equal(t, uint32(5), initialT)
	assert.True(t, requireBFTQuorum)
}

func TestLoadConfigFromEnv_RequireBFTQuorumIsOptIn(t *testing.T) {
	for _, value := range []string{"", "false", "TRUE", "1"} {
		setConfigEnv(t, map[string]string{"REQUIRE_BFT_QUORUM": value})
		_, _, _, _, _, _, _, _, requireBFTQuorum, err := loadConfigFromEnv()
		require.NoError(t, err)
		assert.False(t, requireBFTQuorum, "REQUIRE_BFT_QUORUM=%q", value)
	}
}

// A missing or zero-valued setting must stop the tracker at startup rather
// than let it post a config built from zero values.
func TestLoadConfigFromEnv_Invalid(t *testing.T) {
	for name := range validConfigEnv {
		if name == "REQUIRE_BFT_QUORUM" {
			continue
		}
		t.Run(name+" missing", func(t *testing.T) {
			setConfigEnv(t, map[string]string{name: ""})
			_, _, _, _, _, _, _, _, _, err := loadConfigFromEnv()
			require.ErrorContains(t, err, name)
		})
	}

	for name, value := range map[string]string{
		"CAP_REG_ADDR":              "0x1234",
		"CHAIN_ID":                  "mainnet",
		"DON_ID":                    "4294967296",
		"NODE_CONFIG":               `{"Name":"primary"}`,
		"INITIAL_MASTER_PUBLIC_KEY": "not-hex",
		"INITIAL_T":                 "0",
	} {
		t.Run(name+"="+value, func(t *testing.T) {
			setConfigEnv(t, map[string]string{name: value})
			_, _, _, _, _, _, _, _, _, err := loadConfigFromEnv()
			require.Error(t, err)
		})
	}
}
