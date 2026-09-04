package sts

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts/internal/api"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database"
	stsmetrics "github.com/nais/sts/internal/metrics"
)

func Run(ctx context.Context, cfg config.Config) error {
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

	metricsProvider, err := stsmetrics.NewProvider()
	if err != nil {
		return err
	}
	defer func() {
		if err := metricsProvider.Shutdown(context.Background()); err != nil {
			slog.Error("shut down metrics provider", "error", err)
		}
	}()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default(), metricsProvider.Meter())
	if err != nil {
		return err
	}
	defer pool.Close()

	return api.StartServer(ctx, cfg, pool, metricsProvider)
}
