//go:build integration_test

package integration

import (
	"context"
	"crypto/rsa"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/store"
	"go.opentelemetry.io/otel"
)

func TestNewPoolMigratesPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	dsn := setupPostgres(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	const runners = 4
	pools := make(chan *pgxpool.Pool, runners)
	errs := make(chan error, runners)
	var group sync.WaitGroup
	for range runners {
		group.Add(1)
		go func() {
			defer group.Done()
			pool, err := database.NewPool(ctx, dsn, log, otel.Meter("integration-test"))
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
}

// TODO: remove or rewrite when adding real integration tests
func TestPostgresKeyStore(t *testing.T) {
	ctx := t.Context()
	pool := newTestPool(t)
	st := store.NewPostgresKeyStore(pool, time.Minute)

	if _, err := st.Signer(ctx); err == nil {
		t.Fatal("expected an error without an active signing key")
	}
	if err := st.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}
	// A second call must not create another key.
	if err := st.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Signer(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err := st.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("public keys = %d, want 1", len(keys.Keys))
	}
	if _, ok := keys.Keys[0].Key.(*rsa.PublicKey); !ok {
		t.Errorf("public key type = %T, want *rsa.PublicKey", keys.Keys[0].Key)
	}
}

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()
	dsn := setupPostgres(t)
	pool, err := database.NewPool(ctx, dsn, slog.New(slog.NewTextHandler(io.Discard, nil)), otel.Meter("integration-test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
