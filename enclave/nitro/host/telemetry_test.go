package main

import (
	"context"
	"strings"
	"testing"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTelemetryPublicKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func envGetter(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func validTelemetryEnv() map[string]string {
	return map[string]string{
		envTelemetryEnabled:            "true",
		envTelemetryEndpoint:           "localhost:4317",
		envTelemetryInsecureConnection: "true",
		envTelemetryAuthHeader:         "1:public-key:signature",
		envTelemetryAuthPublicKeyHex:   testTelemetryPublicKey,
		envPodName:                     "enclave-host-0",
		envPodUID:                      "7d9cf36e-b747-4013-b680-061133be0e29",
	}
}

func TestLoadHostTelemetryConfigDisabled(t *testing.T) {
	cfg, err := loadHostTelemetryConfig(envGetter(map[string]string{
		envTelemetryInsecureConnection: "not-a-bool",
	}))

	require.NoError(t, err)
	assert.False(t, cfg.Enabled)
}

func TestLoadHostTelemetryConfigEnabled(t *testing.T) {
	cfg, err := loadHostTelemetryConfig(envGetter(validTelemetryEnv()))

	require.NoError(t, err)
	assert.Equal(t, hostTelemetryConfig{
		Enabled:            true,
		Endpoint:           "localhost:4317",
		InsecureConnection: true,
		AuthHeader:         "1:public-key:signature",
		AuthPublicKeyHex:   testTelemetryPublicKey,
		PodName:            "enclave-host-0",
		PodUID:             "7d9cf36e-b747-4013-b680-061133be0e29",
	}, cfg)
}

func TestLoadHostTelemetryConfigSecure(t *testing.T) {
	values := validTelemetryEnv()
	values[envTelemetryInsecureConnection] = "false"
	values[envTelemetryCACertFile] = "/etc/telemetry/ca.crt"

	cfg, err := loadHostTelemetryConfig(envGetter(values))

	require.NoError(t, err)
	assert.False(t, cfg.InsecureConnection)
	assert.Equal(t, "/etc/telemetry/ca.crt", cfg.CACertFile)
}

func TestLoadHostTelemetryConfigInvalidBool(t *testing.T) {
	tests := []struct {
		name     string
		variable string
	}{
		{name: "enabled", variable: envTelemetryEnabled},
		{name: "insecure connection", variable: envTelemetryInsecureConnection},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validTelemetryEnv()
			values[test.variable] = "not-a-bool"

			_, err := loadHostTelemetryConfig(envGetter(values))

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.variable)
		})
	}
}

func TestLoadHostTelemetryConfigRequiredValues(t *testing.T) {
	tests := []struct {
		name     string
		variable string
	}{
		{name: "endpoint", variable: envTelemetryEndpoint},
		{name: "auth header", variable: envTelemetryAuthHeader},
		{name: "public key", variable: envTelemetryAuthPublicKeyHex},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validTelemetryEnv()
			delete(values, test.variable)

			_, err := loadHostTelemetryConfig(envGetter(values))

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.variable)
		})
	}
}

func TestLoadHostTelemetryConfigInvalidPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		publicKey string
	}{
		{name: "not hex", publicKey: "zz"},
		{name: "wrong length", publicKey: "0123"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validTelemetryEnv()
			values[envTelemetryAuthPublicKeyHex] = test.publicKey

			_, err := loadHostTelemetryConfig(envGetter(values))

			require.Error(t, err)
			assert.Contains(t, err.Error(), envTelemetryAuthPublicKeyHex)
		})
	}
}

func TestLoadHostTelemetryConfigSecureWithoutCA(t *testing.T) {
	values := validTelemetryEnv()
	values[envTelemetryInsecureConnection] = "false"

	_, err := loadHostTelemetryConfig(envGetter(values))

	require.Error(t, err)
	assert.Contains(t, err.Error(), envTelemetryCACertFile)
}

func TestLoadHostTelemetryConfigDoesNotExposeAuthHeader(t *testing.T) {
	values := validTelemetryEnv()
	secret := "sensitive-auth-header"
	values[envTelemetryAuthHeader] = secret
	delete(values, envTelemetryEndpoint)

	_, err := loadHostTelemetryConfig(envGetter(values))

	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), secret))
}

func TestNewHostTelemetryDisabled(t *testing.T) {
	telemetry, err := newHostTelemetry(
		context.Background(),
		hostTelemetryConfig{},
		cllogger.Sugared(cllogger.Nop()),
	)

	require.NoError(t, err)
	assert.NotNil(t, telemetry.meter)
	require.NotNil(t, telemetry.close)
	require.NoError(t, telemetry.close())
	require.NoError(t, telemetry.close())
}
