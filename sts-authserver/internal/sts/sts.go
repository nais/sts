package sts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/ioconvenience"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/store/clientstore"
	"github.com/nais/sts/internal/store/keystore"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sync/errgroup"
)

const (
	clientCacheRefreshInterval = time.Minute
	shutdownTimeout            = 5 * time.Second
)

// Run serves the STS until ctx is cancelled or SIGINT/SIGTERM arrives.
func Run(ctx context.Context, cfg Config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	setupLogger(cfg)

	metricsProvider, err := stsmetrics.NewProvider()
	if err != nil {
		return err
	}
	defer ioconvenience.CloseFunc(context.Background(), metricsProvider.Shutdown)

	// TODO: add an exporter to ship spans; for now this only generates trace and span IDs for logs.
	tracerProvider := sdktrace.NewTracerProvider()
	defer ioconvenience.CloseFunc(context.Background(), tracerProvider.Shutdown)

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default(), metricsProvider.Meter())
	if err != nil {
		return err
	}
	defer pool.Close()

	clientStore, err := clientstore.New(ctx, pool, clientCacheRefreshInterval)
	if err != nil {
		return err
	}
	defer clientStore.Close()

	keyStore, err := keystore.New(ctx, pool, cfg.AuthorizationServerConfig.TokenExpiry)
	if err != nil {
		return err
	}

	api, err := stsApi(ctx, cfg, clientStore, keyStore, metricsProvider, tracerProvider)
	if err != nil {
		return fmt.Errorf("set up api router: %w", err)
	}

	server := httpServer(cfg.BindAddress, api)
	internalServer := httpServer(cfg.InternalBindAddress, internalApi(metricsProvider.Registry(), pool))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		clientStore.Run(gctx)
		return nil
	})
	g.Go(func() error { return keyStore.Run(gctx) })
	g.Go(func() error { return serve(server) })
	g.Go(func() error { return serve(internalServer) })
	g.Go(func() error {
		<-gctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		return errors.Join(server.Shutdown(shutdownCtx), internalServer.Shutdown(shutdownCtx))
	})

	return g.Wait()
}
