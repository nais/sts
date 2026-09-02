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

	cs := store.NewClientStore(pool)
	clients := []*oauth.Client{
		{
			ID:            "env1:namespace1:workload1",
			Environment:   "env1",
			Namespace:     "namespace1",
			Workload:      "workload1",
			Issuers:       []string{""},
			AllowedScopes: []string{"env1:namespace1:workload2"},
		},
		{
			ID:            "env1:namespace1:workload2",
			Environment:   "env1",
			Namespace:     "namespace1",
			Workload:      "workload2",
			Issuers:       []string{""},
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
		OwnerClientID:    "env1:namespace1:workload1",
		ConsumerClientID: "env1:namespace1:workload2",
		Roles:            []string{"reader"},
	}); err != nil {
		return err
	}

	return nil
}
