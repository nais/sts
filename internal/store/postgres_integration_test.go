//go:build integration_test

package store

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()

	container, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
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

func TestPostgresClientStore(t *testing.T) {
	ctx := t.Context()
	pool := newTestPool(t)
	queries := sqlgen.New(pool)

	for _, id := range []string{"caller", "target"} {
		if err := queries.UpsertClient(ctx, sqlgen.UpsertClientParams{
			ID:              id,
			WorkloadIssuer:  "https://issuer.example",
			WorkloadSubject: "system:serviceaccount:default:" + id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := queries.UpsertClientAccess(ctx, sqlgen.UpsertClientAccessParams{
		oauth.ClientID: "caller",
		TargetID:       "target",
		Roles:          []string{"reader"},
	}); err != nil {
		t.Fatal(err)
	}

	store := NewClientStore(pool)

	client, err := store.GetClient(ctx, "caller")
	if err != nil {
		t.Fatal(err)
	}
	if client.WorkloadSubject != "system:serviceaccount:default:caller" {
		t.Errorf("workload subject = %q", client.WorkloadSubject)
	}
	if len(client.AccessControlList.Allowed) != 1 {
		t.Fatalf("access control entries = %d, want 1", len(client.AccessControlList.Allowed))
	}
	entry := client.AccessControlList.Allowed[0]
	if entry.ID != "target" {
		t.Errorf("target = %q, want target", entry.ID)
	}
	if len(entry.Roles) != 1 || entry.Roles[0] != "reader" {
		t.Errorf("roles = %v, want [reader]", entry.Roles)
	}

	if _, err := store.GetClient(ctx, "unknown"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Errorf("unknown client error = %v, want ErrClientNotFound", err)
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
