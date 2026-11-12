//go:build integration_test

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/jwt"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/store/clientstore"
	"github.com/nais/sts/internal/store/keystore"
	"github.com/stretchr/testify/assert"
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

func TestDatabase(t *testing.T) {
	pool := newTestPool(t)

	t.Run("transactions", func(t *testing.T) {
		testWithTx(t, pool)
	})
	t.Run("key store", func(t *testing.T) {
		resetDatabase(t, pool)
		testPostgresKeyStore(t, pool)
	})
	t.Run("client cache", func(t *testing.T) {
		resetDatabase(t, pool)
		testCachedClientStore(t, pool)
	})
	t.Run("authorize target", func(t *testing.T) {
		testAuthorizeTarget(t, pool)
	})
	t.Run("registration store", func(t *testing.T) {
		resetDatabase(t, pool)
		testClientRegistrationStore(t, pool)
	})
}

func testWithTx(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	queries := sqlgen.New(pool)

	params := func(workload string) sqlgen.UpsertClientParams {
		return sqlgen.UpsertClientParams{
			ID:            "environment:namespace:" + workload,
			Environment:   "environment",
			Namespace:     "namespace",
			Name:          workload,
			Issuer:        "https://issuer.example",
			AllowedScopes: []string{"scope"},
		}
	}
	get := func(workload string) (sqlgen.Client, error) {
		return queries.GetClient(t.Context(), sqlgen.GetClientParams{
			Issuer:    "https://issuer.example",
			Namespace: "namespace",
			Name:      workload,
		})
	}

	t.Run("commits on success", func(t *testing.T) {
		err := database.WithTx(t.Context(), pool, func(ctx context.Context, queries *sqlgen.Queries) error {
			_, err := queries.UpsertClient(ctx, params("committed"))
			return err
		})
		require.NoError(t, err)

		_, err = get("committed")
		require.NoError(t, err)
	})

	t.Run("rolls back on error", func(t *testing.T) {
		wantErr := errors.New("fail transaction")
		err := database.WithTx(t.Context(), pool, func(ctx context.Context, queries *sqlgen.Queries) error {
			_, err := queries.UpsertClient(ctx, params("rolled-back"))
			require.NoError(t, err)
			return wantErr
		})
		require.ErrorIs(t, err, wantErr)

		_, err = get("rolled-back")
		require.ErrorIs(t, err, pgx.ErrNoRows)
	})

	t.Run("read-only snapshot applies transaction options", func(t *testing.T) {
		result, err := database.WithReadOnlySnapshot(t.Context(), pool, func(ctx context.Context, _ *sqlgen.Queries) (string, error) {
			tx, ok := database.Tx(ctx)
			require.True(t, ok)

			var isolation, readOnly string
			require.NoError(t, tx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation))
			require.NoError(t, tx.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly))
			require.Equal(t, "repeatable read", isolation)
			require.Equal(t, "on", readOnly)
			return "snapshot", nil
		})
		require.NoError(t, err)
		require.Equal(t, "snapshot", result)
	})

	t.Run("read-only snapshot rejects nesting", func(t *testing.T) {
		err := database.WithTx(t.Context(), pool, func(ctx context.Context, _ *sqlgen.Queries) error {
			_, err := database.WithReadOnlySnapshot(ctx, pool, func(context.Context, *sqlgen.Queries) (struct{}, error) {
				return struct{}{}, nil
			})
			return err
		})
		require.EqualError(t, err, "read-only snapshot cannot run inside an existing transaction")
	})

	t.Run("nested calls reuse outer transaction", func(t *testing.T) {
		wantErr := errors.New("fail outer transaction")
		err := database.WithTx(t.Context(), pool, func(ctx context.Context, queries *sqlgen.Queries) error {
			outerTx, ok := database.Tx(ctx)
			require.True(t, ok)
			_, err := queries.UpsertClient(ctx, params("outer"))
			require.NoError(t, err)

			require.NoError(t, database.WithTx(ctx, pool, func(ctx context.Context, queries *sqlgen.Queries) error {
				innerTx, ok := database.Tx(ctx)
				require.True(t, ok)
				require.Same(t, outerTx, innerTx)
				_, err := queries.UpsertClient(ctx, params("inner"))
				return err
			}))
			return wantErr
		})
		require.ErrorIs(t, err, wantErr)

		_, err = get("outer")
		require.ErrorIs(t, err, pgx.ErrNoRows)
		_, err = get("inner")
		require.ErrorIs(t, err, pgx.ErrNoRows)
	})
}

func testPostgresKeyStore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx := t.Context()
	st, err := keystore.New(ctx, pool, time.Minute)
	require.NoError(t, err)

	_, err = st.Signer()
	require.NoError(t, err)
	keys, err := st.PublicKeys()
	require.NoError(t, err)
	require.Len(t, keys.Keys, 3)
	for _, jwk := range keys.Keys {
		publicKey, ok := jwk.Key.(*ecdsa.PublicKey)
		require.True(t, ok, "public key type = %T", jwk.Key)
		require.Equal(t, elliptic.P256(), publicKey.Curve)
		require.Equal(t, string(jose.ES256), jwk.Algorithm)
		require.True(t, jwk.IsPublic())
	}

	// A second replica must load the existing keys instead of creating another set.
	second, err := keystore.New(ctx, pool, time.Minute)
	require.NoError(t, err)
	secondKeys, err := second.PublicKeys()
	require.NoError(t, err)
	require.Equal(t,
		[]string{keys.Keys[0].KeyID, keys.Keys[1].KeyID, keys.Keys[2].KeyID},
		[]string{secondKeys.Keys[0].KeyID, secondKeys.Keys[1].KeyID, secondKeys.Keys[2].KeyID},
	)

	// Force expiry and rotate concurrently. The advisory lock must allow exactly
	// one rotation while both replicas refresh to the same three-key snapshot.
	_, err = pool.Exec(ctx, "UPDATE rotatable_signing_keys SET expires_at = $1", time.Now().Add(-time.Hour))
	require.NoError(t, err)

	var group sync.WaitGroup
	errs := make(chan error, 2)
	for _, keyStore := range []*keystore.Store{st, second} {
		group.Go(func() {
			errs <- keyStore.RotateSigningKeys(ctx)
		})
	}
	group.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	rotatedKeys, err := st.PublicKeys()
	require.NoError(t, err)
	secondRotatedKeys, err := second.PublicKeys()
	require.NoError(t, err)
	require.Len(t, rotatedKeys.Keys, 3)
	for _, jwk := range rotatedKeys.Keys {
		require.Equal(t, string(jose.ES256), jwk.Algorithm)
	}
	require.Equal(t,
		[]string{rotatedKeys.Keys[0].KeyID, rotatedKeys.Keys[1].KeyID, rotatedKeys.Keys[2].KeyID},
		[]string{secondRotatedKeys.Keys[0].KeyID, secondRotatedKeys.Keys[1].KeyID, secondRotatedKeys.Keys[2].KeyID},
	)
	require.Equal(t, keys.Keys[1].KeyID, rotatedKeys.Keys[0].KeyID)
	require.Equal(t, keys.Keys[2].KeyID, rotatedKeys.Keys[1].KeyID)

	var rows int
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM rotatable_signing_keys").Scan(&rows))
	require.Equal(t, 1, rows)
}

func testCachedClientStore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	t.Run("miss returns client not found", func(t *testing.T) {
		resetClients(t, pool)
		cached, err := clientstore.New(t.Context(), pool, time.Hour)
		require.NoError(t, err)
		defer cached.Close()

		_, err = sqlgen.New(pool).UpsertClient(t.Context(), testClientParams("scope"))
		require.NoError(t, err)

		_, err = cached.Get(t.Context(), testClientClaims())
		assert.ErrorIs(t, err, oauth.ErrClientNotFound)
	})

	t.Run("refreshes after notification", func(t *testing.T) {
		resetClients(t, pool)
		queries := sqlgen.New(pool)
		_, err := queries.UpsertClient(t.Context(), testClientParams("old-scope"))
		require.NoError(t, err)

		cached, err := clientstore.New(t.Context(), pool, time.Hour)
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

		_, err = queries.UpsertClient(t.Context(), testClientParams("new-scope"))
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			client, err := cached.Get(t.Context(), testClientClaims())
			return err == nil && len(client.AllowedScopes) == 1 && client.AllowedScopes[0] == "new-scope"
		}, 5*time.Second, 10*time.Millisecond)
	})
}

func testAuthorizeTarget(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	resetClients(t, pool)

	writer, err := clientstore.New(t.Context(), pool, time.Hour)
	require.NoError(t, err)
	defer writer.Close()

	newClient := func(environment, namespace, name oauth.Name) *oauth.Client {
		client := testClient("scope")
		client.ID = string(oauth.NewClientID(environment, namespace, name))
		client.Environment = string(environment)
		client.Namespace = string(namespace)
		client.Name = string(name)
		return client
	}
	exactWithRoles := newClient("env1", "team-a", "exact-with-roles")
	sameNamespace := newClient("env2", "team-a", "other")
	otherNamespace := newClient("env1", "team-b", "other")

	namespaceTarget := newClient("env1", "target", "namespace")
	namespaceTarget.ConsumerNamespaces = []string{"team-a"}
	require.NoError(t, writer.Save(t.Context(), namespaceTarget, []oauth.AuthorizationPolicy{
		{Consumer: oauth.ClientID(exactWithRoles.ID), Roles: oauth.Roles{"reader"}},
	}, namespaceTarget.Issuer))
	allTarget := newClient("env1", "target", "all")
	allTarget.AllowAllConsumers = true
	require.NoError(t, writer.Save(t.Context(), allTarget, []oauth.AuthorizationPolicy{
		{Consumer: oauth.ClientID(exactWithRoles.ID), Roles: oauth.Roles{"writer"}},
	}, allTarget.Issuer))
	exactTarget := newClient("env1", "target", "exact")
	require.NoError(t, writer.Save(t.Context(), exactTarget, nil, exactTarget.Issuer))

	// A fresh store loads the saved policies in its initial snapshot.
	store, err := clientstore.New(t.Context(), pool, time.Hour)
	require.NoError(t, err)
	defer store.Close()

	tests := map[string]struct {
		consumer  *oauth.Client
		target    *oauth.Client
		wantErr   bool
		wantRoles oauth.Roles
	}{
		"client policy roles":                     {consumer: exactWithRoles, target: namespaceTarget, wantRoles: oauth.Roles{"reader"}},
		"namespace policy in another environment": {consumer: sameNamespace, target: namespaceTarget},
		"other namespace denied":                  {consumer: otherNamespace, target: namespaceTarget, wantErr: true},
		"client policy roles despite allow-all":   {consumer: exactWithRoles, target: allTarget, wantRoles: oauth.Roles{"writer"}},
		"allow-all":                               {consumer: otherNamespace, target: allTarget},
		"no policy denied":                        {consumer: exactWithRoles, target: exactTarget, wantErr: true},
		"unknown target denied":                   {consumer: exactWithRoles, target: newClient("env1", "target", "missing"), wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			roles, err := store.AuthorizeTarget(t.Context(), test.consumer, oauth.TargetScope(test.target.ID))
			if test.wantErr {
				require.ErrorIs(t, err, oauth.ErrTargetUnauthorized)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantRoles, roles)
		})
	}
}

func testClientRegistrationStore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	clients, err := clientstore.New(t.Context(), pool, time.Hour)
	require.NoError(t, err)
	defer clients.Close()
	queries := sqlgen.New(pool)
	oldConsumer := oauth.NewClientID("environment", "namespace", "old-consumer")
	retainedConsumer := oauth.NewClientID("environment", "namespace", "retained-consumer")
	newConsumer := oauth.NewClientID("environment", "namespace", "new-consumer")
	consumer := oauth.NewClientID("environment", "namespace", "consumer")
	missingClient := oauth.NewClientID("environment", "namespace", "missing")

	run := func(name string, test func(*testing.T)) {
		t.Run(name, func(t *testing.T) {
			resetClients(t, pool)
			test(t)
		})
	}

	run("replaces policies, scopes and allow-all", func(t *testing.T) {
		client := testClient("old-scope")
		client.AllowAllConsumers = true
		client.ConsumerNamespaces = []string{"old-namespace", "retained-namespace"}
		oldPolicies := []oauth.AuthorizationPolicy{
			{Owner: oauth.ClientID(client.ID), Consumer: oldConsumer, Roles: oauth.Roles{"old-role"}},
			{Owner: oauth.ClientID(client.ID), Consumer: retainedConsumer, Roles: oauth.Roles{"old-role"}},
		}
		require.NoError(t, clients.Save(t.Context(), client, oldPolicies, client.Issuer))

		replacement := testClient("new-scope")
		replacement.ConsumerNamespaces = []string{"new-namespace", "retained-namespace"}
		newPolicies := []oauth.AuthorizationPolicy{
			{Owner: oauth.ClientID(client.ID), Consumer: retainedConsumer, Roles: oauth.Roles{"new-role"}},
			{Owner: oauth.ClientID(client.ID), Consumer: newConsumer, Roles: oauth.Roles{"new-role"}},
		}
		require.NoError(t, clients.Save(t.Context(), replacement, newPolicies, client.Issuer))

		assertStoredRegistration(t, queries, client.ID, replacement.AllowedScopes, []sqlgen.AuthorizationPolicy{
			{OwnerClientID: client.ID, ConsumerClientID: string(newConsumer), Roles: []string{"new-role"}},
			{OwnerClientID: client.ID, ConsumerClientID: string(retainedConsumer), Roles: []string{"new-role"}},
		})
		stored, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
		require.NoError(t, err)
		require.False(t, stored.AllowAllConsumers)
		require.Equal(t, replacement.ConsumerNamespaces, stored.ConsumerNamespaces)
	})

	run("rolls back on policy failure", func(t *testing.T) {
		client := testClient("old-scope")
		oldPolicies := []oauth.AuthorizationPolicy{{Owner: oauth.ClientID(client.ID), Consumer: consumer, Roles: oauth.Roles{"old-role"}}}
		require.NoError(t, clients.Save(t.Context(), client, oldPolicies, client.Issuer))

		replacement := testClient("new-scope")
		// The store must remain atomic even if a caller bypasses software-statement validation.
		invalidPolicies := []oauth.AuthorizationPolicy{{Owner: oauth.ClientID(client.ID), Consumer: "invalid\x00consumer", Roles: oauth.Roles{"new-role"}}}
		require.Error(t, clients.Save(t.Context(), replacement, invalidPolicies, client.Issuer))

		assertStoredRegistration(t, queries, client.ID, client.AllowedScopes, []sqlgen.AuthorizationPolicy{
			{OwnerClientID: client.ID, ConsumerClientID: string(consumer), Roles: []string{"old-role"}},
		})
	})

	run("updates issuer without changing scopes", func(t *testing.T) {
		client := testClient("scope")
		policies := []oauth.AuthorizationPolicy{{Owner: oauth.ClientID(client.ID), Consumer: consumer, Roles: oauth.Roles{"reader"}}}
		require.NoError(t, clients.Save(t.Context(), client, policies, client.Issuer))

		client.Issuer = "https://new-issuer.example"
		require.NoError(t, clients.Save(t.Context(), client, policies, client.Issuer))

		stored, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
		require.NoError(t, err)
		require.Equal(t, client.Issuer, stored.Issuer)
		assertStoredRegistration(t, queries, client.ID, client.AllowedScopes, []sqlgen.AuthorizationPolicy{
			{OwnerClientID: client.ID, ConsumerClientID: string(consumer), Roles: []string{"reader"}},
		})
	})

	run("notifies only when registration changes", func(t *testing.T) {
		// A fresh connection avoids notifications queued on reused pool connections.
		listener, err := pgx.ConnectConfig(t.Context(), pool.Config().ConnConfig.Copy())
		require.NoError(t, err)
		defer func(listener *pgx.Conn, ctx context.Context) {
			_ = listener.Close(ctx)
		}(listener, context.Background())
		_, err = listener.Exec(t.Context(), "LISTEN sts_cache_changed")
		require.NoError(t, err)

		client := testClient()
		client.AllowedScopes = []string{} // Matches HTTP registration.
		var policies []oauth.AuthorizationPolicy
		steps := []struct {
			name   string
			change func()
			want   int
		}{
			{name: "initial registration", want: 1},
			{name: "identical registration without policies"},
			{name: "adds policies", want: 1, change: func() {
				policies = []oauth.AuthorizationPolicy{
					{Consumer: consumer, Roles: oauth.Roles{"reader"}},
					{Consumer: newConsumer, Roles: oauth.Roles{"writer"}},
				}
			}},
			{name: "identical registration with policies"},
			{name: "reorders policies", change: func() {
				policies[0], policies[1] = policies[1], policies[0]
			}},
			{name: "changes roles", want: 1, change: func() {
				policies[0].Roles = oauth.Roles{"admin"}
			}},
			{name: "changes scopes", want: 1, change: func() {
				client.AllowedScopes = []string{"scope"}
			}},
			{name: "changes issuer", want: 1, change: func() {
				client.Issuer = "https://new-issuer.example"
			}},
			{name: "removes one policy", want: 1, change: func() {
				policies = policies[:1]
			}},
			{name: "identical registration after changes"},
			{name: "removes all policies", want: 1, change: func() {
				policies = nil
			}},
			{name: "identical registration after removing policies"},
			{name: "adds consumer namespaces", want: 1, change: func() {
				client.ConsumerNamespaces = []string{"team-a", "team-b"}
			}},
			{name: "identical registration with consumer namespaces"},
			{name: "removes consumer namespaces", want: 1, change: func() {
				client.ConsumerNamespaces = nil
			}},
			{name: "allows all consumers", want: 1, change: func() {
				client.AllowAllConsumers = true
			}},
			{name: "identical registration allowing all consumers"},
			{name: "disallows all consumers", want: 1, change: func() {
				client.AllowAllConsumers = false
			}},
		}
		for _, step := range steps {
			// These steps intentionally build on the preceding registration.
			if step.change != nil {
				step.change()
			}
			before, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
			if step.name != "initial registration" {
				require.NoError(t, err)
			}
			require.NoError(t, clients.Save(t.Context(), client, policies, client.Issuer), step.name)

			// This marker commits after Save. Reading through it checks for absent
			// or duplicate notifications without relying on a timeout for silence.
			_, err = listener.Exec(t.Context(), "SELECT pg_notify('sts_cache_changed', 'barrier')")
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			count := 0
			for {
				notification, err := listener.WaitForNotification(ctx)
				require.NoError(t, err, step.name)
				if notification.Payload == "barrier" {
					break
				}
				count++
			}
			cancel()
			require.Equal(t, step.want, count, step.name)
			if step.want == 0 {
				after, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
				require.NoError(t, err)
				require.Equal(t, before.UpdatedAt, after.UpdatedAt, step.name)
			}
		}
	})

	run("rejects issuer outside authority", func(t *testing.T) {
		client := testClient("scope")
		require.ErrorIs(t, clients.Save(t.Context(), client, nil, "https://other.example"), oauth.ErrRegistrationUnauthorized)

		_, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
		require.ErrorIs(t, err, pgx.ErrNoRows)
	})

	run("deletes clients", func(t *testing.T) {
		// Deleting the missing client succeeds.
		require.NoError(t, clients.Delete(t.Context(), missingClient, "https://issuer.example"))

		// Another issuer cannot delete this client or its policy for consumer.
		client := testClient("scope")
		policy := oauth.AuthorizationPolicy{Owner: oauth.ClientID(client.ID), Consumer: consumer, Roles: oauth.Roles{"reader"}}
		require.NoError(t, clients.Save(t.Context(), client, []oauth.AuthorizationPolicy{policy}, client.Issuer))
		require.ErrorIs(t, clients.Delete(t.Context(), oauth.ClientID(client.ID), "https://other.example"), oauth.ErrRegistrationUnauthorized)

		// Read PostgreSQL directly so a stale cache cannot hide a deleted client or policy.
		assertStoredRegistration(t, queries, client.ID, client.AllowedScopes, []sqlgen.AuthorizationPolicy{
			{OwnerClientID: client.ID, ConsumerClientID: string(consumer), Roles: []string{"reader"}},
		})

		// The client's issuer can delete both the client and its policy for consumer.
		require.NoError(t, clients.Delete(t.Context(), oauth.ClientID(client.ID), client.Issuer))
		_, err := queries.GetClientByIDForUpdate(t.Context(), client.ID)
		require.ErrorIs(t, err, pgx.ErrNoRows)

		_, err = queries.GetAuthorizationPolicy(t.Context(), sqlgen.GetAuthorizationPolicyParams{
			OwnerClientID: client.ID, ConsumerClientID: string(consumer),
		})
		require.ErrorIs(t, err, pgx.ErrNoRows)
	})
}

func assertStoredRegistration(t *testing.T, queries *sqlgen.Queries, clientID string, scopes []string, policies []sqlgen.AuthorizationPolicy) {
	t.Helper()
	stored, err := queries.GetClientByIDForUpdate(t.Context(), clientID)
	require.NoError(t, err)
	require.Equal(t, scopes, stored.AllowedScopes)
	storedPolicies, err := queries.ListAuthorizationPolicies(t.Context())
	require.NoError(t, err)
	require.Equal(t, policies, storedPolicies)
}

func resetDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(t.Context(), "TRUNCATE authorization_policies, clients, rotatable_signing_keys")
	require.NoError(t, err)
}

func resetClients(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(t.Context(), "TRUNCATE authorization_policies, clients")
	require.NoError(t, err)
}

func testClient(scopes ...string) *oauth.Client {
	return &oauth.Client{Client: sqlgen.Client{
		ID:            string(oauth.NewClientID("environment", "namespace", "workload")),
		Environment:   "environment",
		Namespace:     "namespace",
		Name:          "workload",
		Issuer:        "https://issuer.example",
		AllowedScopes: scopes,
	}}
}

func testClientParams(scopes ...string) sqlgen.UpsertClientParams {
	client := testClient(scopes...)
	return sqlgen.UpsertClientParams{
		ID:            client.ID,
		Environment:   client.Environment,
		Namespace:     client.Namespace,
		Name:          client.Name,
		Issuer:        client.Issuer,
		AllowedScopes: client.AllowedScopes,
	}
}

func testClientClaims() *jwt.AccessTokenClaims {
	return &jwt.AccessTokenClaims{
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
