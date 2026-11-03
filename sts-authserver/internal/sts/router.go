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
	healthEndpoint      = "/healthz"
	readinessEndpoint   = "/readyz"
	readinessTimeout    = 2 * time.Second
	instrumentationName = "nais-sts"
)

func stsApi(
	ctx context.Context,
	cfg config.Config,
	clientStore oauth.ClientStore,
	keyStore oauth.KeyStore,
	provider *stsmetrics.Provider,
) (http.Handler, error) {
	r := chi.NewRouter()

	httpMetrics := otelchimetric.NewBaseConfig(
		instrumentationName,
		otelchimetric.WithMeterProvider(provider.MeterProvider()),
	)
	r.Use(
		otelchimetric.NewServerActiveRequests(httpMetrics),
		otelchimetric.NewServerRequestDuration(httpMetrics),
		otelchimetric.NewServerRequestBodySize(httpMetrics),
		otelchimetric.NewServerResponseBodySize(httpMetrics),
	)
	// TODO: set up a tracer provider and propagator; without them these spans
	// are no-ops and logs never get trace_id/span_id.
	r.Use(otelchi.Middleware(
		instrumentationName,
		otelchi.WithChiRoutes(r),
		otelchi.WithRequestMethodInSpanName(true),
	))

	httpClient, err := newHTTPClient(cfg.AdditionalCAFile)
	if err != nil {
		return nil, fmt.Errorf("create upstream HTTP client: %w", err)
	}

	authServer, err := oauth.NewAuthorizationServer(ctx, httpClient, cfg.AuthorizationServerConfig, clientStore, keyStore, provider.Metrics())
	if err != nil {
		return nil, fmt.Errorf("initialize authorization server: %w", err)
	}
	registrationApi, err := registration.NewApi(ctx, httpClient, cfg.AuthorizationServerConfig, clientStore)
	if err != nil {
		return nil, fmt.Errorf("initialize client registration handler: %w", err)
	}

	r.Get(api.OAuthDiscoveryPath, authServer.DiscoveryEndpoint())
	r.Post(api.TokenPath, authServer.TokenEndpoint())
	r.Get(api.JWKSPath, authServer.JwksEndpoint())
	r.Post(api.RegistrationPath, registrationApi.PostEndpoint())
	r.Delete(fmt.Sprintf("%s/{id}", api.RegistrationPath), registrationApi.DeleteEndpoint())
	return r, nil
}

func internalApi(registry *prometheus.Registry, pool *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()
	r.HandleFunc(healthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	r.HandleFunc(readinessEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// Fail fast, so an exhausted pool does not block the probe until its own timeout.
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP)
	return r
}
