package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts/internal/api"
	"github.com/nais/sts/internal/config"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		slog.Error("loading STS config", "error", err)
		os.Exit(1)
	}
	if err := api.Run(ctx, cfg); err != nil {
		slog.Error("error running STS", "error", err)
		os.Exit(1)
	}
}
