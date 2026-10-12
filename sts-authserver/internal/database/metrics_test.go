package database

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestQueryAttributes(t *testing.T) {
	tests := []struct {
		query         string
		wantOperation string
		wantSummary   string
	}{
		{query: "-- name: GetClient :one\nSELECT * FROM clients", wantOperation: "SELECT", wantSummary: "GetClient"},
		{query: " INSERT INTO clients VALUES ($1)", wantOperation: "INSERT", wantSummary: "INSERT"},
		{query: "CREATE TABLE clients (id text)", wantOperation: "OTHER", wantSummary: "OTHER"},
		{query: "", wantOperation: "OTHER", wantSummary: "OTHER"},
	}
	for _, tt := range tests {
		operation := queryOperation(tt.query)
		if operation != tt.wantOperation {
			t.Errorf("queryOperation(%q) = %q, want %q", tt.query, operation, tt.wantOperation)
		}
		if got := querySummary(tt.query, operation); got != tt.wantSummary {
			t.Errorf("querySummary(%q) = %q, want %q", tt.query, got, tt.wantSummary)
		}
	}
}

func TestDatabaseMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})

	meter := provider.Meter("test")
	metrics, err := newDatabaseMetrics(meter)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), "postgres://test@127.0.0.1:1/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := metrics.registerPoolMetrics(meter, pool); err != nil {
		t.Fatal(err)
	}

	queryCtx := metrics.TraceQueryStart(t.Context(), nil, pgx.TraceQueryStartData{SQL: "-- name: GetClient :one\nSELECT 1"})
	trace := queryCtx.Value(queryTraceContextKey{}).(queryTraceData)
	if trace.summary != "GetClient" {
		t.Errorf("query summary = %q, want GetClient", trace.summary)
	}
	metrics.TraceQueryEnd(queryCtx, nil, pgx.TraceQueryEndData{})
	acquireCtx := metrics.TraceAcquireStart(t.Context(), nil, pgxpool.TraceAcquireStartData{})
	metrics.TraceAcquireEnd(acquireCtx, nil, pgxpool.TraceAcquireEndData{Err: errors.New("pool exhausted")})

	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &resourceMetrics); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"sts.database.queries":             false,
		"db.client.operation.duration":     false,
		"sts.database.connection.acquires": false,
		"db.client.connection.wait_time":   false,
		"db.client.connection.count":       false,
		"db.client.connection.max":         false,
	}
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, recorded := range scope.Metrics {
			if _, ok := want[recorded.Name]; ok {
				want[recorded.Name] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %q was not recorded", name)
		}
	}
}
