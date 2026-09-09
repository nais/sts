//go:build integration_test

package integration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var key crypto.PrivateKey

type testFixtures struct {
	Environment    string
	Namespace      string
	ClientWorkload string
	ClientID       string
	Target         string
	Role           string
	TokenExpiry    time.Duration
}

var fixtures = testFixtures{
	Environment:    "env1",
	Namespace:      "namespace1",
	ClientWorkload: "workload1",
	ClientID:       "env1:namespace1:workload1",
	Target:         "env1:namespace1:workload2",
	Role:           "reader",
	TokenExpiry:    time.Hour,
}

func init() {
	key, _ = rsa.GenerateKey(rand.Reader, 2048)
}

type testServer string

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

func startSts(t testing.TB, oauthServer testServer) (testServer, testServer) {
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

		if err := json.NewEncoder(w).Encode((jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{
				Key:       key.(*rsa.PrivateKey).Public(),
				KeyID:     "foo",
				Algorithm: "RS256",
				Use:       "sig",
			},
		}})); err != nil {
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
			Issuer:           oauth.Issuer(server.Endpoint()),
			ExpectedAudience: "nais",
			ClientAuthIssuers: []oauth.Issuer{
				oauth.Issuer(oauthServer.Endpoint("env1")),
				oauth.Issuer(oauthServer.Endpoint("env2")),
			},
			SubjectTokenIssuers: []oauth.Issuer{
				oauth.Issuer(oauthServer.Endpoint("subject1")),
				oauth.Issuer(oauthServer.Endpoint("subject2")),
			},
			TokenExpiry: fixtures.TokenExpiry,
		},
		Registrators: []*registration.ClientRegistratorConfig{
			{
				Issuer:        oauthServer.Endpoint("env1"),
				Subject:       "system:serviceaccount:namespace1:registrator1",
				ClientJwksUri: registratorServer.URL,
				RequiredAlgs:  []string{"RS256"},
			},
			{
				Issuer:        oauthServer.Endpoint("env2"),
				Subject:       "system:serviceaccount:namespace1:registrator2",
				ClientJwksUri: registratorServer.URL,
				RequiredAlgs:  []string{"RS256"},
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
	return server, testServer(internalAddr)
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
	if err := queries.UpsertKubernetesClient(t.Context(), sqlgen.UpsertKubernetesClientParams{
		ID:            fixtures.ClientID,
		Environment:   fixtures.Environment,
		Namespace:     fixtures.Namespace,
		Workload:      fixtures.ClientWorkload,
		Issuer:        oauthServer.Endpoint(fixtures.Environment),
		AllowedScopes: []string{fixtures.Target},
	}); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertAuthorizationPolicy(t.Context(), sqlgen.UpsertAuthorizationPolicyParams{
		OwnerClientID:    fixtures.ClientID,
		ConsumerClientID: fixtures.Target,
		Roles:            []string{fixtures.Role},
	}); err != nil {
		t.Fatal(err)
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
