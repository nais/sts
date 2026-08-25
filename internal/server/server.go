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
	"github.com/nais/sts/internal/oauth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/sync/errgroup"
)

const shutdownTimeout = 5 * time.Second

func Run(ctx context.Context, cfg config.Config) error {
	registrations, err := oauth.LoadRegistrationStore(cfg.RegistrationsFile)
	if err != nil {
		return err
	}
	publicListener, err := net.Listen("tcp", cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("listen on public address %q: %w", cfg.BindAddress, err)
	}
	internalListener, err := net.Listen("tcp", cfg.InternalBindAddress)
	if err != nil {
		_ = publicListener.Close()
		return fmt.Errorf("listen on internal address %q: %w", cfg.InternalBindAddress, err)
	}
	router, err := publicRouter(cfg.Issuer, registrations)
	if err != nil {
		return err
	}

	publicServer := newHTTPServer(router)
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

func publicRouter(issuer string, registrations *oauth.RegistrationStore) (http.Handler, error) {
	router := chi.NewRouter()
	e := &op.Endpoints{
		Token:   op.NewEndpoint("/token"),
		JwksURI: op.NewEndpoint("/jwks"),
	}
	s, err := oauth.NewServer(issuer, e, registrations)
	if err != nil {
		return nil, err
	}
	router.Use(contextMiddleware(issuer))
	router.HandleFunc(oidc.DiscoveryEndpoint, discoveryHandler(e))
	router.Mount("/", s)
	return router, nil
}

func contextMiddleware(issuer string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(op.ContextWithIssuer(r.Context(), issuer))
			next.ServeHTTP(w, r)
		})
	}
}

func discoveryHandler(endpoints *op.Endpoints) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer := op.IssuerFromContext(r.Context())
		op.Discover(w, &oidc.DiscoveryConfiguration{
			Issuer:        issuer,
			TokenEndpoint: endpoints.Token.Absolute(issuer),
			JwksURI:       endpoints.JwksURI.Absolute(issuer),
			GrantTypesSupported: []oidc.GrantType{
				oidc.GrantTypeClientCredentials,
				oidc.GrantTypeTokenExchange,
			},
			TokenEndpointAuthMethodsSupported: []oidc.AuthMethod{
				oidc.AuthMethodPrivateKeyJWT,
			},
			TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
		})
	}
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
