package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/ioconvenience"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

const (
	shutdownTimeout  = 5 * time.Second
	readinessTimeout = 2 * time.Second
)

const (
	clientCacheRefreshInterval = time.Minute
	signingKeyCacheTTL         = time.Minute
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

	return startServer(ctx, cfg, pool, metricsProvider)
}

func startServer(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, provider *stsmetrics.Provider) error {
	publicListener, err := net.Listen("tcp", cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("listen on public address %q: %w", cfg.BindAddress, err)
	}
	defer ioconvenience.CloseWithLog(publicListener, slog.Default())

	internalListener, err := net.Listen("tcp", cfg.InternalBindAddress)
	if err != nil {
		return fmt.Errorf("listen on internal address %q: %w", cfg.InternalBindAddress, err)
	}
	defer ioconvenience.CloseWithLog(internalListener, slog.Default())

	clientStore, err := store.NewCachedClientStore(ctx,
		pool,
		clientCacheRefreshInterval,
		slog.With(slog.Default(), "component", "authorizationserver"))
	if err != nil {
		return err
	}
	defer clientStore.Close()

	keyStore, err := store.NewPostgresKeyStore(ctx, pool, signingKeyCacheTTL)
	if err != nil {
		return err
	}

	authServer, err := oauth.NewAuthorizationServer(ctx, cfg.AuthorizationServerConfig, clientStore, keyStore, provider.Metrics())
	if err != nil {
		return fmt.Errorf("initialize authorization server: %w", err)
	}

	publicServer := httpServer(authorizationServerRouter(authServer, provider))
	internalServer := httpServer(internalRouter(provider.Registry(), pool))

	slog.Info("servers listening",
		"public_port", publicListener.Addr().(*net.TCPAddr).Port,
		"internal_port", internalListener.Addr().(*net.TCPAddr).Port,
	)
	issuer := strings.TrimRight(cfg.AuthorizationServerConfig.Issuer, "/")
	slog.Info("server endpoints",
		"discovery_url", issuer+oauthDiscoveryEndpoint,
		"token_url", issuer+tokenEndpoint,
		"jwks_url", issuer+jwksEndpoint,
	)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(publicServer, publicListener) })
	group.Go(func() error { return serve(internalServer, internalListener) })
	group.Go(func() error {
		clientStore.Run(groupCtx)
		return nil
	})
	group.Go(func() error { return shutdown(groupCtx, "public", publicServer) })
	group.Go(func() error { return shutdown(groupCtx, "internal", internalServer) })
	return group.Wait()
}

func serve(server *http.Server, listener net.Listener) error {
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func shutdown(ctx context.Context, name string, server *http.Server) error {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down %s server: %w", name, err)
	}
	return nil
}

func httpServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func internalRouter(registry *prometheus.Registry, pool *pgxpool.Pool) http.Handler {
	router := chi.NewRouter()
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readinessHandler(pool))
	router.Get("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP)
	return router
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

func readinessHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fail fast, so an exhausted pool does not block the probe until its own timeout.
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		healthHandler(w, r)
	}
}
