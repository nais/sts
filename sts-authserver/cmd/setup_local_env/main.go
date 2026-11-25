package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/sts"
	"go.opentelemetry.io/otel"
)

func main() {
	k3d := flag.Bool("k3d", false, "seed the k3d impersonation demo client")
	flag.Parse()
	ctx := context.Background()
	if err := run(ctx, *k3d); err != nil {
		log.Printf("error running setup_local_env: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, k3d bool) error {
	cfg, err := sts.LoadConfig()
	if err != nil {
		return err
	}

	options := &slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, options)

	slog.SetDefault(slog.New(handler))
	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default(), otel.Meter("github.com/nais/sts/setup-local-env"))
	if err != nil {
		return err
	}
	defer pool.Close()

	queries := sqlgen.New(pool)
	impersonator := oauth.Impersonator{Issuer: "http://localhost:3004/people", Subject: "person1"}
	if k3d {
		return upsertClient(ctx, queries, sqlgen.UpsertClientParams{
			ID:          "sts-operator-dev:sts-demo:impersonation-demo",
			Environment: "sts-operator-dev",
			Namespace:   "sts-demo",
			Name:        "impersonation-demo",
			Issuer:      string(cfg.AuthorizationServerConfig.ClientAuthIssuers["cluster-local"].Issuer),
			AuthorizationPolicy: oauth.AuthorizationPolicy{
				AllowedImpersonators: []oauth.Impersonator{impersonator},
			},
		})
	}

	clients := []sqlgen.UpsertClientParams{
		{
			ID:          "env1:namespace1:workload1",
			Environment: "env1",
			Namespace:   "namespace1",
			Name:        "workload1",
			Issuer:      "http://localhost:3004/env1",
			AuthorizationPolicy: oauth.AuthorizationPolicy{
				AllowedScopes:        []string{"env1:namespace1:workload2"},
				AllowedImpersonators: []oauth.Impersonator{impersonator},
			},
		},
		{
			ID:          "env1:namespace1:workload2",
			Environment: "env1",
			Namespace:   "namespace1",
			Name:        "workload2",
			Issuer:      "http://localhost:3004/env1",
			AuthorizationPolicy: oauth.AuthorizationPolicy{
				Clients: []oauth.AuthorizedClient{
					{ClientID: "env1:namespace1:workload1", Roles: oauth.Roles{"reader"}},
				},
			},
		},
	}

	for _, client := range clients {
		if err := upsertClient(ctx, queries, client); err != nil {
			return err
		}
	}

	return nil
}

func upsertClient(ctx context.Context, queries *sqlgen.Queries, params sqlgen.UpsertClientParams) error {
	// UpsertClient returns pgx.ErrNoRows when the stored client is unchanged.
	if _, err := queries.UpsertClient(ctx, params); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}
