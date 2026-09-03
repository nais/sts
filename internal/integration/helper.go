//go:build integration_test

package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/sts"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgres(t *testing.T) string {
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

func startSts(t *testing.T, oauthServerURL string) string {
	t.Helper()

	dsn := setupPostgres(t)

	addr := fmt.Sprintf("localhost:%d", getFreePort(t))
	internalAddr := fmt.Sprintf("localhost:%d", getFreePort(t))

	cfg := config.Config{
		BindAddress:         addr,
		DatabaseURL:         dsn,
		InternalBindAddress: internalAddr,
		LogLevel:            slog.LevelDebug,
		LogFormat:           "text",
		AuthorizationServerConfig: oauth.AuthorizationServerConfig{
			Issuer:           addr,
			ExpectedAudience: "nais",
			ClientAuthIssuers: []oauth.Issuer{
				oauth.Issuer(fmt.Sprintf("%s/env1", oauthServerURL)),
				oauth.Issuer(fmt.Sprintf("%s/env2", oauthServerURL)),
			},
			SubjectTokenIssuers: []oauth.Issuer{
				oauth.Issuer(fmt.Sprintf("%s/subject1", oauthServerURL)),
				oauth.Issuer(fmt.Sprintf("%s/subject2", oauthServerURL)),
			},
			TokenExpiry: 1 * time.Hour,
		},
	}

	ctx := t.Context()
	go func() {
		_ = sts.Run(ctx, cfg)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/readyz", internalAddr))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if time.Now().After(deadline) {
		t.Fatal("timeout waiting for STS readiness")
	}

	return fmt.Sprintf("http://%s", addr)
}

func startMockOAuthServer(t *testing.T) string {
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

	addr, err := container.PortEndpoint(ctx, "8080/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func getFreePort(t *testing.T) int {
	t.Helper()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP address: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen on TCP address: %v", err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}
