//go:build integration_test

package integration

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/store"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
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
	st, err := store.NewPostgresKeyStore(ctx, pool, time.Minute)
	require.NoError(t, err)

	// A second call must not create another key.
	if err := st.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}

	// A third call must not create another key.
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

func TestCachedClientStoreFallsBackToPostgresOnMiss(t *testing.T) {
	pool := newTestPool(t)
	cached, err := store.NewCachedClientStore(t.Context(), pool, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer cached.Close()

	direct := store.NewClientStore(pool)
	require.NoError(t, direct.Save(t.Context(), testClient("scope")))

	client, err := cached.Get(t.Context(), testClientClaims())
	require.NoError(t, err)
	require.Equal(t, []string{"scope"}, client.AllowedScopes)
}

func TestCachedClientStoreRefreshesAfterNotification(t *testing.T) {
	pool := newTestPool(t)
	direct := store.NewClientStore(pool)
	require.NoError(t, direct.Save(t.Context(), testClient("old-scope")))

	cached, err := store.NewCachedClientStore(t.Context(), pool, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cached.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	require.NoError(t, direct.Save(t.Context(), testClient("new-scope")))
	require.Eventually(t, func() bool {
		client, err := cached.Get(t.Context(), testClientClaims())
		return err == nil && len(client.AllowedScopes) == 1 && client.AllowedScopes[0] == "new-scope"
	}, 5*time.Second, 10*time.Millisecond)
}

func testClient(scopes ...string) *oauth.Client {
	return &oauth.Client{KubernetesClient: sqlgen.KubernetesClient{
		ID:            "environment:namespace:workload",
		Environment:   "environment",
		Namespace:     "namespace",
		Workload:      "workload",
		Issuer:        "https://issuer.example",
		AllowedScopes: scopes,
	}}
}

func testClientClaims() *oauth.AccessTokenClaims {
	return &oauth.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{Issuer: "https://issuer.example"},
		Claims: map[string]json.RawMessage{
			"kubernetes.io": json.RawMessage(`{"namespace":"namespace","serviceaccount":{"name":"workload"}}`),
		},
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
