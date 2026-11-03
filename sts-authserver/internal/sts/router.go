package sts

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/config"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/riandyrn/otelchi"
	otelchimetric "github.com/riandyrn/otelchi/metric"
)

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/readyz"
	readinessTimeout  = 2 * time.Second
)

func stsApi(
	ctx context.Context,
	cfg config.Config,
	clientStore oauth.ClientStore,
	keyStore oauth.KeyStore,
	provider *stsmetrics.Provider,
) (http.Handler, error) {
	httpClient, err := newHTTPClient(cfg.AdditionalCAFile)
	if err != nil {
		return nil, fmt.Errorf("create upstream HTTP client: %w", err)
	}

	router := chi.NewRouter()
	router.Use(RequestLogging)

	httpMetrics := otelchimetric.NewBaseConfig(
		"nais-sts",
		otelchimetric.WithMeterProvider(provider.MeterProvider()),
	)
	router.Use(
		otelchimetric.NewServerActiveRequests(httpMetrics),
		otelchimetric.NewServerRequestDuration(httpMetrics),
		otelchimetric.NewServerRequestBodySize(httpMetrics),
		otelchimetric.NewServerResponseBodySize(httpMetrics),
	)
	router.Use(otelchi.Middleware(
		"nais-sts",
		otelchi.WithChiRoutes(router),
		otelchi.WithRequestMethodInSpanName(true),
	))

	authServer, err := oauth.NewAuthorizationServer(ctx, httpClient, cfg.AuthorizationServerConfig, clientStore, keyStore, provider.Metrics())
	if err != nil {
		return nil, fmt.Errorf("initialize authorization server: %w", err)
	}
	registrationApi, err := registration.NewApi(ctx, httpClient, cfg.AuthorizationServerConfig, clientStore)
	if err != nil {
		return nil, fmt.Errorf("initialize client registration handler: %w", err)
	}

	router.Get(api.OAuthDiscoveryPath, authServer.DiscoveryEndpoint())
	router.Post(api.TokenPath, authServer.TokenEndpoint())
	router.Get(api.JWKSPath, authServer.JwksEndpoint())
	router.Post(api.RegistrationPath, registrationApi.PostEndpoint())
	router.Delete(fmt.Sprintf("%s/{id}", api.RegistrationPath), registrationApi.DeleteEndpoint())
	return router, nil
}

func internalApi(registry *prometheus.Registry, pool *pgxpool.Pool) http.Handler {
	router := chi.NewRouter()
	router.Use(RequestLogging)
	router.HandleFunc(healthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	router.HandleFunc(readinessEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// Fail fast, so an exhausted pool does not block the probe until its own timeout.
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	router.Get("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP)
	return router
}
