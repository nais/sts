package sts

import (
	"context"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	"github.com/nais/sts/internal/api"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database"
)

func Run(ctx context.Context) error {
	_ = godotenv.Load(".env")

	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}

	options := &slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, options)
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, options)
	}
	slog.SetDefault(slog.New(handler))
	slog.Info("configuration loaded",
		"bind_address", cfg.BindAddress,
		"internal_bind_address", cfg.InternalBindAddress,
		"issuer", cfg.AuthorizationServerConfig.Issuer,
		"log_level", cfg.LogLevel.String(),
		"log_format", cfg.LogFormat,
	)

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default())
	if err != nil {
		return err
	}
	defer pool.Close()

	return api.StartServer(ctx, cfg, pool)
}
