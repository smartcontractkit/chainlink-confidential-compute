package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

const (
	hostInstrumentationScope = "github.com/smartcontractkit/confidential-compute/enclave/nitro/host"
	beholderAuthHeader       = "X-Beholder-Node-Auth-Token"

	envTelemetryEnabled            = "CL_TELEMETRY_ENABLED"
	envTelemetryEndpoint           = "CL_TELEMETRY_ENDPOINT"
	envTelemetryInsecureConnection = "CL_TELEMETRY_INSECURE_CONNECTION"
	envTelemetryCACertFile         = "CL_TELEMETRY_CA_CERT_FILE"
	envTelemetryAuthHeader         = "CL_TELEMETRY_AUTH_HEADER"
	envTelemetryAuthPublicKeyHex   = "CL_TELEMETRY_AUTH_PUB_KEY_HEX"
	envPodName                     = "POD_NAME"
	envPodUID                      = "POD_UID"
)

type hostTelemetryConfig struct {
	Enabled            bool
	Endpoint           string
	InsecureConnection bool
	CACertFile         string
	AuthHeader         string
	AuthPublicKeyHex   string
	PodName            string
	PodUID             string
}

type hostTelemetry struct {
	meter metric.Meter
	close func() error
}

func loadHostTelemetryConfig(getenv func(string) string) (hostTelemetryConfig, error) {
	cfg := hostTelemetryConfig{
		Endpoint:         strings.TrimSpace(getenv(envTelemetryEndpoint)),
		CACertFile:       strings.TrimSpace(getenv(envTelemetryCACertFile)),
		AuthHeader:       getenv(envTelemetryAuthHeader),
		AuthPublicKeyHex: strings.TrimSpace(getenv(envTelemetryAuthPublicKeyHex)),
		PodName:          strings.TrimSpace(getenv(envPodName)),
		PodUID:           strings.TrimSpace(getenv(envPodUID)),
	}

	var err error
	cfg.Enabled, err = parseEnvBool(envTelemetryEnabled, getenv(envTelemetryEnabled), false)
	if err != nil {
		return hostTelemetryConfig{}, err
	}
	if !cfg.Enabled {
		return cfg, nil
	}

	cfg.InsecureConnection, err = parseEnvBool(
		envTelemetryInsecureConnection,
		getenv(envTelemetryInsecureConnection),
		false,
	)
	if err != nil {
		return hostTelemetryConfig{}, err
	}
	if cfg.Endpoint == "" {
		return hostTelemetryConfig{}, fmt.Errorf("%s is required when telemetry is enabled", envTelemetryEndpoint)
	}
	if cfg.AuthHeader == "" {
		return hostTelemetryConfig{}, fmt.Errorf("%s is required when telemetry is enabled", envTelemetryAuthHeader)
	}
	publicKey, err := hex.DecodeString(cfg.AuthPublicKeyHex)
	if err != nil || len(publicKey) != 32 {
		return hostTelemetryConfig{}, fmt.Errorf("%s must contain a 32-byte hex public key", envTelemetryAuthPublicKeyHex)
	}
	if !cfg.InsecureConnection && cfg.CACertFile == "" {
		return hostTelemetryConfig{}, fmt.Errorf("%s is required for a secure telemetry connection", envTelemetryCACertFile)
	}
	return cfg, nil
}

func parseEnvBool(name, raw string, defaultValue bool) (bool, error) {
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", name, err)
	}
	return value, nil
}

func newHostTelemetry(ctx context.Context, cfg hostTelemetryConfig, lggr cllogger.SugaredLogger) (hostTelemetry, error) {
	if !cfg.Enabled {
		return hostTelemetry{
			meter: noop.NewMeterProvider().Meter(hostInstrumentationScope),
			close: func() error { return nil },
		}, nil
	}

	instanceID := cfg.PodUID
	if instanceID == "" {
		var err error
		instanceID, err = os.Hostname()
		if err != nil {
			return hostTelemetry{}, fmt.Errorf("resolve telemetry service instance ID: %w", err)
		}
	}

	resourceAttributes := []attribute.KeyValue{
		attribute.String("service.name", "confidential-compute-enclave-host"),
		attribute.String("service.instance.id", instanceID),
		attribute.String("enclave.type", "aws-nitro"),
	}
	if cfg.PodName != "" {
		resourceAttributes = append(resourceAttributes, attribute.String("k8s.pod.name", cfg.PodName))
	}
	if cfg.PodUID != "" {
		resourceAttributes = append(resourceAttributes, attribute.String("k8s.pod.uid", cfg.PodUID))
	}

	beholderCfg := beholder.DefaultConfig()
	beholderCfg.OtelExporterGRPCEndpoint = cfg.Endpoint
	beholderCfg.OtelExporterHTTPEndpoint = ""
	beholderCfg.InsecureConnection = cfg.InsecureConnection
	beholderCfg.CACertFile = cfg.CACertFile
	beholderCfg.ResourceAttributes = append(beholderCfg.ResourceAttributes, resourceAttributes...)
	beholderCfg.AuthHeaders = map[string]string{beholderAuthHeader: cfg.AuthHeader}
	beholderCfg.AuthHeadersTTL = 0
	beholderCfg.AuthPublicKeyHex = cfg.AuthPublicKeyHex
	beholderCfg.TraceSampleRatio = 0
	beholderCfg.LogStreamingEnabled = false

	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		lggr.Errorw("telemetry export error", "error", err)
	}))

	client, err := beholder.NewClient(beholderCfg)
	if err != nil {
		return hostTelemetry{}, fmt.Errorf("create Beholder client: %w", err)
	}
	if err := client.Start(ctx); err != nil {
		_ = client.Close()
		return hostTelemetry{}, fmt.Errorf("start Beholder client: %w", err)
	}

	namedClient := client.ForName(hostInstrumentationScope)
	return hostTelemetry{meter: namedClient.Meter, close: client.Close}, nil
}
