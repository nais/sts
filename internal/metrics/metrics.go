package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.opentelemetry.io/otel/attribute"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var durationBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type Provider struct {
	registry      *prometheus.Registry
	meterProvider *sdkmetric.MeterProvider
	metrics       *Metrics
}

func NewProvider() (*Provider, error) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("create Prometheus metrics exporter: %w", err)
	}
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	metrics, err := New(meterProvider.Meter("github.com/nais/sts"))
	if err != nil {
		return nil, err
	}
	return &Provider{registry: registry, meterProvider: meterProvider, metrics: metrics}, nil
}

func (p *Provider) Registry() *prometheus.Registry {
	return p.registry
}

func (p *Provider) MeterProvider() metric.MeterProvider {
	return p.meterProvider
}

func (p *Provider) Meter() metric.Meter {
	return p.meterProvider.Meter("github.com/nais/sts")
}

func (p *Provider) Metrics() *Metrics {
	return p.metrics
}

func (p *Provider) Shutdown(ctx context.Context) error {
	return p.meterProvider.Shutdown(ctx)
}

type Metrics struct {
	stepDuration metric.Float64Histogram
}

func New(meter metric.Meter) (*Metrics, error) {
	stepDuration, err := meter.Float64Histogram(
		"sts.token.step.duration",
		metric.WithDescription("Time spent in each token issuance step."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(durationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create token step duration: %w", err)
	}
	return &Metrics{stepDuration: stepDuration}, nil
}

func (m *Metrics) ObserveTokenStep(ctx context.Context, step string, start time.Time, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	m.stepDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(
		attribute.String("step", step),
		attribute.String("outcome", outcome),
	))
}
