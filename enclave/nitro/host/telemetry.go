package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const (
	hostInstrumentationScope = "github.com/smartcontractkit/confidential-compute/enclave/nitro/host"
	defaultHostServiceName   = "confidential-compute-enclave-host"

	envOTLPEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"
)

type hostTelemetryConfig struct {
	Endpoint string
}

func (c hostTelemetryConfig) enabled() bool {
	return c.Endpoint != ""
}

type hostTelemetry struct {
	meter metric.Meter
	close func(context.Context) error
}

type metricExporterFactory func(context.Context, string) (sdkmetric.Exporter, error)

// An explicitly configured OTLP endpoint enables telemetry; without one the
// host stays no-op for local development and tests.
func loadHostTelemetryConfig(getenv func(string) string) hostTelemetryConfig {
	return hostTelemetryConfig{
		Endpoint: strings.TrimSpace(getenv(envOTLPEndpoint)),
	}
}

func newOTLPMetricExporter(ctx context.Context, endpoint string) (sdkmetric.Exporter, error) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse OTLP metrics endpoint: %w", err)
	}
	scheme := strings.ToLower(endpointURL.Scheme)
	if (scheme != "http" && scheme != "https") || endpointURL.Host == "" {
		return nil, fmt.Errorf("OTLP metrics endpoint must use an http or https URL with a host")
	}
	if endpointURL.RawQuery != "" || endpointURL.Fragment != "" {
		return nil, fmt.Errorf("OTLP metrics endpoint must not contain a query or fragment")
	}

	// The exporter reads the remaining standard OTLP settings, including TLS,
	// headers, compression, and timeout, directly from OTEL_EXPORTER_OTLP_*.
	return otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpointURL(endpoint))
}

func newHostResource(ctx context.Context) (*resource.Resource, error) {
	// Pod identity is supplied by the platform collector's Kubernetes
	// attributes processor rather than deployment-specific host environment.
	attrs := []attribute.KeyValue{
		attribute.String("service.name", defaultHostServiceName),
		attribute.String("enclave.type", "aws-nitro"),
	}

	res, err := resource.Merge(resource.DefaultWithContext(ctx), resource.NewSchemaless(attrs...))
	if err != nil {
		return nil, fmt.Errorf("create telemetry resource: %w", err)
	}
	return res, nil
}

func newHostTelemetry(ctx context.Context, cfg hostTelemetryConfig, lggr cllogger.SugaredLogger) (hostTelemetry, error) {
	return newHostTelemetryWithExporter(ctx, cfg, lggr, newOTLPMetricExporter)
}

func newHostTelemetryWithExporter(
	ctx context.Context,
	cfg hostTelemetryConfig,
	lggr cllogger.SugaredLogger,
	newExporter metricExporterFactory,
) (hostTelemetry, error) {
	if !cfg.enabled() {
		return hostTelemetry{
			meter: noop.NewMeterProvider().Meter(hostInstrumentationScope),
			close: func(context.Context) error { return nil },
		}, nil
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		lggr.Errorw("telemetry export error", "error", err)
	}))

	res, err := newHostResource(ctx)
	if err != nil {
		return hostTelemetry{}, err
	}
	exporter, err := newExporter(ctx, cfg.Endpoint)
	if err != nil {
		return hostTelemetry{}, fmt.Errorf("create OTLP metric exporter: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	var shutdownOnce sync.Once
	var shutdownErr error

	return hostTelemetry{
		meter: provider.Meter(hostInstrumentationScope),
		close: func(ctx context.Context) error {
			shutdownOnce.Do(func() {
				shutdownErr = provider.Shutdown(ctx)
			})
			return shutdownErr
		},
	}, nil
}
