package sts

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/server"
)

func Run(ctx context.Context) error {
	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	})))

	return server.Run(ctx, cfg)
}
