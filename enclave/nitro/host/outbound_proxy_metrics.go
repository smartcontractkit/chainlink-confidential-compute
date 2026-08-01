package main

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type outboundProxyMetrics interface {
	sessionDelta(cid uint32, delta int64)
	tunnelDelta(cid uint32, delta int64)
	connect(outcome string, duration time.Duration)
	dnsRequest(outcome string, duration time.Duration)
	bytes(direction string, count int64)
	capacityRejected()
	forcedDrain()
}

type noopOutboundProxyMetrics struct{}

func (noopOutboundProxyMetrics) sessionDelta(uint32, int64)       {}
func (noopOutboundProxyMetrics) tunnelDelta(uint32, int64)        {}
func (noopOutboundProxyMetrics) connect(string, time.Duration)    {}
func (noopOutboundProxyMetrics) dnsRequest(string, time.Duration) {}
func (noopOutboundProxyMetrics) bytes(string, int64)              {}
func (noopOutboundProxyMetrics) capacityRejected()                {}
func (noopOutboundProxyMetrics) forcedDrain()                     {}

type otelOutboundProxyMetrics struct {
	sessionsActive metric.Int64UpDownCounter
	tunnelsActive  metric.Int64UpDownCounter
	connects       metric.Int64Counter
	connectTime    metric.Float64Histogram
	dnsRequests    metric.Int64Counter
	dnsTime        metric.Float64Histogram
	transferred    metric.Int64Counter
	rejections     metric.Int64Counter
	forcedDrains   metric.Int64Counter
}

func newOutboundProxyMetrics(meter metric.Meter) (*otelOutboundProxyMetrics, error) {
	sessions, err := meter.Int64UpDownCounter("confidential_compute.enclave.outbound.sessions.active", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound sessions metric: %w", err)
	}
	tunnels, err := meter.Int64UpDownCounter("confidential_compute.enclave.outbound.connections.active", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound tunnels metric: %w", err)
	}
	connects, err := meter.Int64Counter("confidential_compute.enclave.outbound.connects", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound connects metric: %w", err)
	}
	connectTime, err := meter.Float64Histogram("confidential_compute.enclave.outbound.connect.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("create outbound connect duration metric: %w", err)
	}
	dnsRequests, err := meter.Int64Counter("confidential_compute.enclave.outbound.dns.requests", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound DNS requests metric: %w", err)
	}
	dnsTime, err := meter.Float64Histogram("confidential_compute.enclave.outbound.dns.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("create outbound DNS duration metric: %w", err)
	}
	transferred, err := meter.Int64Counter("confidential_compute.enclave.outbound.bytes", metric.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("create outbound bytes metric: %w", err)
	}
	rejections, err := meter.Int64Counter("confidential_compute.enclave.outbound.capacity.rejections", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound rejections metric: %w", err)
	}
	forcedDrains, err := meter.Int64Counter("confidential_compute.enclave.outbound.drains.forced", metric.WithUnit("1"))
	if err != nil {
		return nil, fmt.Errorf("create outbound forced drains metric: %w", err)
	}
	return &otelOutboundProxyMetrics{
		sessionsActive: sessions,
		tunnelsActive:  tunnels,
		connects:       connects,
		connectTime:    connectTime,
		dnsRequests:    dnsRequests,
		dnsTime:        dnsTime,
		transferred:    transferred,
		rejections:     rejections,
		forcedDrains:   forcedDrains,
	}, nil
}

func (m *otelOutboundProxyMetrics) sessionDelta(cid uint32, delta int64) {
	m.sessionsActive.Add(context.Background(), delta, metric.WithAttributes(attribute.Int64("enclave.cid", int64(cid))))
}

func (m *otelOutboundProxyMetrics) tunnelDelta(cid uint32, delta int64) {
	m.tunnelsActive.Add(context.Background(), delta, metric.WithAttributes(attribute.Int64("enclave.cid", int64(cid))))
}

func (m *otelOutboundProxyMetrics) connect(outcome string, duration time.Duration) {
	attrs := metric.WithAttributes(attribute.String("outcome", outcome))
	m.connects.Add(context.Background(), 1, attrs)
	m.connectTime.Record(context.Background(), duration.Seconds(), attrs)
}

func (m *otelOutboundProxyMetrics) dnsRequest(outcome string, duration time.Duration) {
	attrs := metric.WithAttributes(attribute.String("outcome", outcome))
	m.dnsRequests.Add(context.Background(), 1, attrs)
	m.dnsTime.Record(context.Background(), duration.Seconds(), attrs)
}

func (m *otelOutboundProxyMetrics) bytes(direction string, count int64) {
	m.transferred.Add(context.Background(), count, metric.WithAttributes(attribute.String("direction", direction)))
}

func (m *otelOutboundProxyMetrics) capacityRejected() {
	m.rejections.Add(context.Background(), 1)
}

func (m *otelOutboundProxyMetrics) forcedDrain() {
	m.forcedDrains.Add(context.Background(), 1)
}
