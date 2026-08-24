package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/sync/errgroup"
)

const shutdownTimeout = 5 * time.Second

func Run(ctx context.Context, cfg config.Config) error {
	publicListener, err := net.Listen("tcp", cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("listen on public address %q: %w", cfg.BindAddress, err)
	}
	internalListener, err := net.Listen("tcp", cfg.InternalBindAddress)
	if err != nil {
		_ = publicListener.Close()
		return fmt.Errorf("listen on internal address %q: %w", cfg.InternalBindAddress, err)
	}

	publicServer := newHTTPServer(publicRouter())
	internalServer := newHTTPServer(internalRouter(newRegistry()))

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

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func publicRouter() http.Handler {
	router := chi.NewRouter()
	router.Mount("/", op.RegisterServer(op.UnimplementedServer{}, *op.DefaultEndpoints))
	return router
}

func internalRouter(registry *prometheus.Registry) http.Handler {
	router := chi.NewRouter()
	router.Get("/healthz", healthHandler)
	router.Get("/readyz", healthHandler)
	router.Get("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP)
	return router
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func newRegistry() *prometheus.Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return registry
}
