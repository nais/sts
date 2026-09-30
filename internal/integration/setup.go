//go:build integration_test

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/api"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/nais/sts/internal/jwk"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var key = func() jose.JSONWebKey {
	key, err := jwk.Generate()
	if err != nil {
		panic(err)
	}
	return key
}()

type testFixtures struct {
	Client1          clientFixture
	Client2          clientFixture
	Client3          clientFixture
	RegisteredTarget clientFixture
	Role             string
	TokenExpiry      time.Duration
}

type clientFixture struct {
	Environment string
	Namespace   string
	Workload    string
	ID          string
}

var fixtures = testFixtures{
	Client1:          clientFixture{Environment: "env1", Namespace: "namespace1", Workload: "workload1", ID: "env1:namespace1:workload1"},
	Client2:          clientFixture{Environment: "env1", Namespace: "namespace1", Workload: "workload2", ID: "env1:namespace1:workload2"},
	Client3:          clientFixture{Environment: "env1", Namespace: "namespace1", Workload: "workload3", ID: "env1:namespace1:workload3"},
	RegisteredTarget: clientFixture{Environment: "env1", Namespace: "namespace1", Workload: "registered-workload", ID: "env1:namespace1:registered-workload"},
	Role:             "reader",
	TokenExpiry:      time.Hour,
}

type (
	testServer       string
	testServerConfig struct {
		Address          testServer
		InternalAddress  testServer
		AuthServerConfig oauth.AuthorizationServerConfig
	}
)

func (s testServer) Endpoint(paths ...string) string {
	return (&url.URL{Scheme: "http", Host: string(s)}).JoinPath(paths...).String()
}

func startMockOAuthServer(t testing.TB) testServer {
	t.Helper()
	ctx := t.Context()

	container, err := testcontainers.Run(ctx,
		"ghcr.io/navikt/mock-oauth2-server:latest",
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithEnv(map[string]string{
			"JSON_CONFIG_PATH": "/config/mock-oauth2-server.json",
		}),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath:      "../../mock-oauth2-server.json",
			ContainerFilePath: "/config/mock-oauth2-server.json",
			FileMode:          0o644,
		}),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8080/tcp")),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Errorf("terminate mock OAuth2 container: %v", err)
		}
	})

	addr, err := container.PortEndpoint(ctx, "8080/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	return testServer(addr)
}

func startSts(t testing.TB, oauthServer testServer) testServerConfig {
	t.Helper()

	dsn := setupPostgres(t)

	addr := fmt.Sprintf("localhost:%d", getFreePort(t))
	internalAddr := fmt.Sprintf("localhost:%d", getFreePort(t))
	server := testServer(addr)

	registratorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := "application/jwk-set+json"
		if r.Header.Get("Accept") == "application/json" {
			contentType = "application/json"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Add("Vary", "Accept")

		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.Public()}}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	cfg := config.Config{
		BindAddress:         addr,
		DatabaseURL:         dsn,
		InternalBindAddress: internalAddr,
		LogLevel:            slog.LevelDebug,
		LogFormat:           "text",
		AuthorizationServerConfig: oauth.AuthorizationServerConfig{
			Issuer:                      oauth.Issuer(server.Endpoint()),
			ExpectedAudience:            "nais",
			ClientAuthSigningAlgorithms: []string{"RS256"},
			MaxClientAuthTokenLifetime:  time.Hour,
			ClientAuthIssuers: []oauth.Issuer{
				oauth.Issuer(oauthServer.Endpoint("env1")),
				oauth.Issuer(oauthServer.Endpoint("env2")),
			},
			SubjectTokenIssuers: map[oauth.Issuer]string{
				oauth.Issuer(oauthServer.Endpoint("subject1")): "name1",
				oauth.Issuer(oauthServer.Endpoint("subject2")): "name2",
			},
			TokenExpiry: fixtures.TokenExpiry,
		},
		Registrators: []*registration.ClientRegistratorConfig{
			{
				Issuer:        oauthServer.Endpoint("env1"),
				Subject:       "system:serviceaccount:namespace1:registrator1",
				ClientJwksUri: registratorServer.URL,
				RequiredAlgs:  []string{string(jwk.Algorithm)},
			},
			{
				Issuer:        oauthServer.Endpoint("env2"),
				Subject:       "system:serviceaccount:namespace1:registrator2",
				ClientJwksUri: registratorServer.URL,
				RequiredAlgs:  []string{string(jwk.Algorithm)},
			},
		},
	}

	ctx := t.Context()
	go func() {
		_ = api.Run(ctx, cfg)
	}()

	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/readyz", internalAddr))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("timeout waiting for STS readiness")
	}

	seedSts(t, dsn, oauthServer)
	return testServerConfig{
		Address:          server,
		InternalAddress:  testServer(internalAddr),
		AuthServerConfig: cfg.AuthorizationServerConfig,
	}
}

func setupPostgres(t testing.TB) string {
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
	return dsn
}

func seedSts(t testing.TB, dsn string, oauthServer testServer) {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	queries := sqlgen.New(pool)
	for _, client := range []clientFixture{fixtures.Client1, fixtures.Client2, fixtures.Client3} {
		if _, err := queries.UpsertKubernetesClient(t.Context(), sqlgen.UpsertKubernetesClientParams{
			ID:            client.ID,
			Environment:   client.Environment,
			Namespace:     client.Namespace,
			Workload:      client.Workload,
			Issuer:        oauthServer.Endpoint(client.Environment),
			AllowedScopes: []string{},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range []struct {
		consumer clientFixture
		target   clientFixture
	}{
		{consumer: fixtures.Client1, target: fixtures.Client2},
		{consumer: fixtures.Client2, target: fixtures.Client3},
	} {
		if err := queries.UpsertAuthorizationPolicy(t.Context(), sqlgen.UpsertAuthorizationPolicyParams{
			OwnerClientID:    pair.target.ID,
			ConsumerClientID: pair.consumer.ID,
			Roles:            []string{fixtures.Role},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func getFreePort(t testing.TB) int {
	t.Helper()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP address: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen on TCP address: %v", err)
	}
	defer ioconvenience.CloseWithLog(l, slog.Default())
	return l.Addr().(*net.TCPAddr).Port
}
