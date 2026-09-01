package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/store"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Printf("error running setup_local_env: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	err := godotenv.Load(".env")
	if err != nil {
		return err
	}

	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}

	options := &slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, options)

	slog.SetDefault(slog.New(handler))
	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default())
	if err != nil {
		return err
	}
	defer pool.Close()

	// TODO: should issuer be stored as part of client or not?
	// TODO: introduce token issuer for local use instead of depending on live connection to kubernetes

	cs := store.NewClientStore(pool)
	clients := []*oauth.Client{
		{
			ID:            "system:serviceaccount:trong:debug",
			Environment:   "local",
			Namespace:     "namespace",
			Workload:      "workload",
			Issuers:       []string{"https://container.googleapis.com/v1/projects/nais-dev-cdea/locations/europe-north1/clusters/nais-dev"},
			AllowedScopes: []string{"tenant:cluster:namespace:other-workload"},
		},
		{
			ID:            "tenant:cluster:namespace:other-workload",
			Environment:   "local",
			Namespace:     "namespace",
			Workload:      "other-workload",
			Issuers:       []string{"https://container.googleapis.com/v1/projects/nais-dev-cdea/locations/europe-north1/clusters/nais-dev"},
			AllowedScopes: []string{},
		},
	}

	for _, client := range clients {
		err := cs.Save(ctx, client)
		if err != nil {
			return err
		}
	}

	queries := sqlgen.New(pool)
	if err := queries.UpsertAuthorizationPolicy(ctx, sqlgen.UpsertAuthorizationPolicyParams{
		OwnerClientID:    "system:serviceaccount:trong:debug",
		ConsumerClientID: "tenant:cluster:namespace:other-workload",
		Roles:            []string{"reader"},
	}); err != nil {
		return err
	}

	return nil
}
