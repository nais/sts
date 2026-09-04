package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"go.opentelemetry.io/otel/metric"
)

//go:embed migrations/0*.sql
var migrations embed.FS

const migrationTimeout = 2 * time.Minute

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
	defer ioconvenience.CloseWithLog(db, log)

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
	defer ioconvenience.CloseWithLog(provider, log)

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}
