package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func envGetter(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestLoadHostTelemetryConfigDisabledByDefault(t *testing.T) {
	cfg := loadHostTelemetryConfig(envGetter(nil))

	assert.False(t, cfg.enabled())
	assert.Empty(t, cfg.Endpoint)
}

func TestLoadHostTelemetryConfigEndpoint(t *testing.T) {
	cfg := loadHostTelemetryConfig(envGetter(map[string]string{
		envOTLPEndpoint: " http://daemon-collector.open-telemetry.svc.cluster.local:4317 ",
	}))

	assert.Equal(t, hostTelemetryConfig{
		Endpoint: "http://daemon-collector.open-telemetry.svc.cluster.local:4317",
	}, cfg)
	assert.True(t, cfg.enabled())
}

func TestNewHostTelemetryDisabled(t *testing.T) {
	exporterCreated := false
	telemetry, err := newHostTelemetryWithExporter(
		context.Background(),
		hostTelemetryConfig{},
		cllogger.Sugared(cllogger.Nop()),
		func(context.Context, string) (sdkmetric.Exporter, error) {
			exporterCreated = true
			return nil, nil
		},
	)

	require.NoError(t, err)
	assert.False(t, exporterCreated)
	assert.NotNil(t, telemetry.meter)
	require.NotNil(t, telemetry.close)
	require.NoError(t, telemetry.close(context.Background()))
	require.NoError(t, telemetry.close(context.Background()))
}

func TestNewHostTelemetryExportsMetricsWithHostResource(t *testing.T) {
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "3600000")
	exporter := newRecordingMetricExporter()
	var gotEndpoint string
	telemetry, err := newHostTelemetryWithExporter(
		context.Background(),
		hostTelemetryConfig{
			Endpoint: "http://collector:4317",
		},
		cllogger.Sugared(cllogger.Nop()),
		func(_ context.Context, endpoint string) (sdkmetric.Exporter, error) {
			gotEndpoint = endpoint
			return exporter, nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, "http://collector:4317", gotEndpoint)

	counter, err := telemetry.meter.Int64Counter("test.counter")
	require.NoError(t, err)
	counter.Add(context.Background(), 1)

	require.NoError(t, telemetry.close(context.Background()))
	require.NoError(t, telemetry.close(context.Background()))
	assert.Equal(t, 1, exporter.shutdownCount())

	exported := exporter.lastExport()
	require.NotNil(t, exported)
	attrs := exported.Resource.Set()
	assertResourceAttribute(t, attrs, "service.name", defaultHostServiceName)
	assertResourceAttribute(t, attrs, "enclave.type", "aws-nitro")
}

func TestNewHostTelemetryReturnsExporterError(t *testing.T) {
	expected := errors.New("bad endpoint")
	_, err := newHostTelemetryWithExporter(
		context.Background(),
		hostTelemetryConfig{Endpoint: "://invalid"},
		cllogger.Sugared(cllogger.Nop()),
		func(context.Context, string) (sdkmetric.Exporter, error) {
			return nil, expected
		},
	)

	require.ErrorIs(t, err, expected)
	assert.Contains(t, err.Error(), "create OTLP metric exporter")
}

func TestNewOTLPMetricExporterRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"://invalid",
		"collector:4317",
		"grpc://collector:4317",
		"http://collector:4317?query=value",
		"http://collector:4317#fragment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := newOTLPMetricExporter(context.Background(), endpoint)
			require.Error(t, err)
		})
	}
}

func TestHostTelemetryShutdownHonorsContext(t *testing.T) {
	exporter := newRecordingMetricExporter()
	exporter.shutdown = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	telemetry, err := newHostTelemetryWithExporter(
		context.Background(),
		hostTelemetryConfig{
			Endpoint: "http://collector:4317",
		},
		cllogger.Sugared(cllogger.Nop()),
		func(context.Context, string) (sdkmetric.Exporter, error) {
			return exporter, nil
		},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = telemetry.close(ctx)

	require.ErrorIs(t, err, context.Canceled)
}

func assertResourceAttribute(t *testing.T, attrs *attribute.Set, key, expected string) {
	t.Helper()
	value, ok := attrs.Value(attribute.Key(key))
	require.True(t, ok, "resource attribute %s was missing", key)
	assert.Equal(t, expected, value.AsString())
}

type recordingMetricExporter struct {
	mu             sync.Mutex
	exported       *metricdata.ResourceMetrics
	shutdown       func(context.Context) error
	shutdownCalled int
}

func newRecordingMetricExporter() *recordingMetricExporter {
	return &recordingMetricExporter{
		shutdown: func(context.Context) error { return nil },
	}
}

func (*recordingMetricExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (*recordingMetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}

func (e *recordingMetricExporter) Export(_ context.Context, data *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := *data
	e.exported = &snapshot
	return nil
}

func (*recordingMetricExporter) ForceFlush(ctx context.Context) error {
	return ctx.Err()
}

func (e *recordingMetricExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	e.shutdownCalled++
	shutdown := e.shutdown
	e.mu.Unlock()
	return shutdown(ctx)
}

func (e *recordingMetricExporter) lastExport() *metricdata.ResourceMetrics {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exported
}

func (e *recordingMetricExporter) shutdownCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shutdownCalled
}
