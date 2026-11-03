package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"go.opentelemetry.io/otel/metric"
)

//go:embed migrations/0*.sql
var migrations embed.FS

const migrationTimeout = 2 * time.Minute

type txContextKey struct{}

func NewPool(ctx context.Context, dsn string, log *slog.Logger, meter metric.Meter) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}

	if runtime.NumCPU() < 20 {
		config.MaxConns = 20
	}

	dbMetrics, err := newDatabaseMetrics(meter)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.Tracer = dbMetrics

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	if err = dbMetrics.registerPoolMetrics(meter, pool); err != nil {
		pool.Close()
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	if err := migrate(ctx, pool, log); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func Tx(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txContextKey{}).(pgx.Tx)
	return tx, ok
}

// WithTx runs fn with transaction-bound queries. Nested calls reuse the active transaction.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, *sqlgen.Queries) error) error {
	if tx, ok := Tx(ctx); ok {
		return fn(ctx, sqlgen.New(tx))
	}
	_, err := withTxResult(ctx, pool, pgx.TxOptions{}, func(ctx context.Context, queries *sqlgen.Queries) (struct{}, error) {
		return struct{}{}, fn(ctx, queries)
	})
	return err
}

// WithReadOnlySnapshot loads a value in a read-only transaction where every
// query sees the same database snapshot. It rejects nesting because an existing
// transaction may not provide those guarantees.
func WithReadOnlySnapshot[T any](ctx context.Context, pool *pgxpool.Pool, load func(context.Context, *sqlgen.Queries) (T, error)) (T, error) {
	var zero T
	if _, ok := Tx(ctx); ok {
		return zero, errors.New("read-only snapshot cannot run inside an existing transaction")
	}
	result, err := withTxResult(ctx, pool, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	}, load)
	if err != nil {
		return zero, fmt.Errorf("read-only snapshot: %w", err)
	}
	return result, nil
}

// ReadOnlySnapshotLoader adapts a query loader for use by a cache or another
// component that loads values using only a context.
func ReadOnlySnapshotLoader[T any](pool *pgxpool.Pool, load func(context.Context, *sqlgen.Queries) (T, error)) func(context.Context) (T, error) {
	return func(ctx context.Context) (T, error) {
		return WithReadOnlySnapshot(ctx, pool, load)
	}
}

func withTxResult[T any](ctx context.Context, pool *pgxpool.Pool, options pgx.TxOptions, fn func(context.Context, *sqlgen.Queries) (T, error)) (T, error) {
	var zero T
	tx, err := pool.BeginTx(ctx, options)
	if err != nil {
		return zero, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := fn(context.WithValue(ctx, txContextKey{}, tx), sqlgen.New(tx))
	if err != nil {
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, fmt.Errorf("commit tx: %w", err)
	}
	return result, nil
}

type gooseLogger struct {
	log *slog.Logger
}

func (g gooseLogger) Fatalf(format string, args ...any) {
	g.log.Error(fmt.Sprintf(format, args...))
}

func (g gooseLogger) Printf(format string, args ...any) {
	g.log.Info(fmt.Sprintf(format, args...))
}

func migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	// Every replica migrates at startup, so bound the wait for the migration lock.
	ctx, cancel := context.WithTimeout(ctx, migrationTimeout)
	defer cancel()

	db := stdlib.OpenDBFromPool(pool)
	defer ioconvenience.Close(db)

	migrationFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("open migrations: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		migrationFS,
		goose.WithLogger(gooseLogger{log: log.With("subsystem", "database-migration")}),
		goose.WithSessionLocker(locker),
	)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	defer ioconvenience.Close(provider)

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}
