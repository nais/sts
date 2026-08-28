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
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

const shutdownTimeout = 5 * time.Second

func StartServer(ctx context.Context, cfg config.Config) error {
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

	router, err := authorizationServerRouter(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setting up auth server; %w", err)
	}

	publicServer := httpServer(router)
	internalServer := httpServer(internalRouter(prometheusRegistry()))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(publicServer, publicListener) })
	group.Go(func() error { return serve(internalServer, internalListener) })
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

func internalRouter(registry *prometheus.Registry) http.Handler {
	router := chi.NewRouter()
	router.Get("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP)
	return router
}

func prometheusRegistry() *prometheus.Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return registry
}
