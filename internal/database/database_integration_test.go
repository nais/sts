//go:build integration_test

package database

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestNewPoolMigratesPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := postgres.Run(
		ctx,
		"postgres:18",
		postgres.WithDatabase("sts"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Errorf("terminate Postgres container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	const runners = 4
	pools := make(chan *pgxpool.Pool, runners)
	errs := make(chan error, runners)
	var group sync.WaitGroup
	for range runners {
		group.Add(1)
		go func() {
			defer group.Done()
			pool, err := NewPool(ctx, dsn, log)
			if err != nil {
				errs <- err
				return
			}
			pools <- pool
		}()
	}
	group.Wait()
	close(errs)
	close(pools)
	for err := range errs {
		t.Fatal(err)
	}
	for pool := range pools {
		pool.Close()
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var version int64
	if err := pool.QueryRow(ctx, "SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	if version != int64(len(entries)) {
		t.Fatalf("latest migration version = %d, want %d", version, len(entries))
	}
}
