//go:build integration_test

package store

import (
	"context"
	"crypto/rsa"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()

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
	pool, err := database.NewPool(ctx, dsn, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TODO: remove or rewrite when adding real integration tests
func TestPostgresClientStore(t *testing.T) {
	ctx := t.Context()
	pool := newTestPool(t)
	queries := sqlgen.New(pool)

	if err := queries.UpsertKubernetesClient(ctx, sqlgen.UpsertKubernetesClientParams{
		ID:            "caller",
		Environment:   "dev",
		Namespace:     "default",
		Workload:      "caller",
		Issuers:       []string{"https://issuer.example"},
		AllowedScopes: []string{"api://target/.default"},
	}); err != nil {
		t.Fatal(err)
	}

	store := NewClientStore(pool)

	client, err := store.Get(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if client.Environment != "dev" {
		t.Errorf("environment = %q, want dev", client.Environment)
	}
	if client.Namespace != "default" {
		t.Errorf("namespace = %q, want default", client.Namespace)
	}
	if client.Workload != "caller" {
		t.Errorf("workload = %q, want caller", client.Workload)
	}
	if len(client.Issuers) != 1 || client.Issuers[0] != "https://issuer.example" {
		t.Errorf("issuers = %v, want [https://issuer.example]", client.Issuers)
	}
	if len(client.AllowedScopes) != 1 || client.AllowedScopes[0] != "api://target/.default" {
		t.Errorf("allowed scopes = %v, want [api://target/.default]", client.AllowedScopes)
	}
}

func TestPostgresKeyStore(t *testing.T) {
	ctx := t.Context()
	pool := newTestPool(t)
	store := NewPostgresKeyStore(pool, time.Minute)

	if _, err := store.Signer(ctx); err == nil {
		t.Fatal("expected an error without an active signing key")
	}
	if err := store.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}
	// A second call must not create another key.
	if err := store.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Signer(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err := store.PublicKeys(ctx)
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
