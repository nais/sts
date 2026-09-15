package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/semconv/v1.37.0/dbconv"
)

const databasePoolName = "sts"

var databaseDurationBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

type (
	queryTraceContextKey   struct{}
	acquireTraceContextKey struct{}
)

type queryTraceData struct {
	start     time.Time
	operation string
	summary   string
}

type databaseMetrics struct {
	queryCount      metric.Int64Counter
	queryDuration   dbconv.ClientOperationDuration
	acquireCount    metric.Int64Counter
	acquireDuration dbconv.ClientConnectionWaitTime
}

func newDatabaseMetrics(meter metric.Meter) (*databaseMetrics, error) {
	queryCount, err := meter.Int64Counter(
		"sts.database.queries",
		metric.WithDescription("Number of PostgreSQL queries executed."),
	)
	if err != nil {
		return nil, fmt.Errorf("create database query counter: %w", err)
	}
	queryDuration, err := dbconv.NewClientOperationDuration(
		meter,
		metric.WithExplicitBucketBoundaries(databaseDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create database query duration: %w", err)
	}
	acquireCount, err := meter.Int64Counter(
		"sts.database.connection.acquires",
		metric.WithDescription("Number of PostgreSQL connection acquisition attempts."),
	)
	if err != nil {
		return nil, fmt.Errorf("create database connection acquire counter: %w", err)
	}
	acquireDuration, err := dbconv.NewClientConnectionWaitTime(
		meter,
		metric.WithExplicitBucketBoundaries(databaseDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("create database connection acquire duration: %w", err)
	}
	return &databaseMetrics{
		queryCount:      queryCount,
		queryDuration:   queryDuration,
		acquireCount:    acquireCount,
		acquireDuration: acquireDuration,
	}, nil
}

func (m *databaseMetrics) registerPoolMetrics(meter metric.Meter, pool *pgxpool.Pool) error {
	connectionCountConvention := dbconv.ClientConnectionCount{}
	connections, err := meter.Int64ObservableGauge(
		connectionCountConvention.Name(),
		metric.WithDescription(connectionCountConvention.Description()),
		metric.WithUnit(connectionCountConvention.Unit()),
	)
	if err != nil {
		return fmt.Errorf("create database connection gauge: %w", err)
	}
	connectionMaxConvention := dbconv.ClientConnectionMax{}
	maxConnections, err := meter.Int64ObservableGauge(
		connectionMaxConvention.Name(),
		metric.WithDescription(connectionMaxConvention.Description()),
		metric.WithUnit(connectionMaxConvention.Unit()),
	)
	if err != nil {
		return fmt.Errorf("create maximum database connection gauge: %w", err)
	}
	_, err = meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		stats := pool.Stat()
		poolAttribute := semconv.DBClientConnectionPoolName(databasePoolName)
		observer.ObserveInt64(connections, int64(stats.IdleConns()), metric.WithAttributes(semconv.DBSystemNamePostgreSQL, poolAttribute, semconv.DBClientConnectionStateIdle))
		observer.ObserveInt64(connections, int64(stats.AcquiredConns()), metric.WithAttributes(semconv.DBSystemNamePostgreSQL, poolAttribute, semconv.DBClientConnectionStateUsed))
		observer.ObserveInt64(maxConnections, int64(stats.MaxConns()), metric.WithAttributes(semconv.DBSystemNamePostgreSQL, poolAttribute))
		return nil
	}, connections, maxConnections)
	if err != nil {
		return fmt.Errorf("register database pool metrics: %w", err)
	}
	return nil
}

func (m *databaseMetrics) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	operation := queryOperation(data.SQL)
	return context.WithValue(ctx, queryTraceContextKey{}, queryTraceData{
		start:     time.Now(),
		operation: operation,
		summary:   querySummary(data.SQL, operation),
	})
}

func (m *databaseMetrics) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	trace, ok := ctx.Value(queryTraceContextKey{}).(queryTraceData)
	if !ok {
		return
	}
	attributes := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		semconv.DBOperationName(trace.operation),
		semconv.DBQuerySummary(trace.summary),
		attribute.String("outcome", outcome(data.Err)),
	}
	m.queryCount.Add(ctx, 1, metric.WithAttributes(attributes...))
	m.queryDuration.Record(ctx, time.Since(trace.start).Seconds(), dbconv.SystemNamePostgreSQL, attributes[1:]...)
}

func (m *databaseMetrics) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, acquireTraceContextKey{}, time.Now())
}

func (m *databaseMetrics) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	start, ok := ctx.Value(acquireTraceContextKey{}).(time.Time)
	if !ok {
		return
	}
	attributes := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		attribute.String("outcome", outcome(data.Err)),
	}
	m.acquireCount.Add(ctx, 1, metric.WithAttributes(attributes...))
	m.acquireDuration.Record(ctx, time.Since(start).Seconds(), databasePoolName, attributes...)
}

func queryOperation(query string) string {
	for line := range strings.SplitSeq(query, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		operation := strings.ToUpper(fields[0])
		switch operation {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "ROLLBACK":
			return operation
		default:
			return "OTHER"
		}
	}
	return "OTHER"
}

func querySummary(query, fallback string) string {
	for line := range strings.SplitSeq(query, "\n") {
		line = strings.TrimSpace(line)
		name, ok := strings.CutPrefix(line, "-- name:")
		if !ok {
			continue
		}
		fields := strings.Fields(name)
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return fallback
}

func outcome(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

var (
	_ pgx.QueryTracer       = (*databaseMetrics)(nil)
	_ pgxpool.AcquireTracer = (*databaseMetrics)(nil)
)
