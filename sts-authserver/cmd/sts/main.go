package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/server"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		slog.Error("loading STS config", "error", err)
		os.Exit(1)
	}
	if err := server.Run(ctx, cfg); err != nil {
		slog.Error("error running STS", "error", err)
		os.Exit(1)
	}
}
