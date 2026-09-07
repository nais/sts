package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/config"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/store"
	"github.com/riandyrn/otelchi"
	otelchimetric "github.com/riandyrn/otelchi/metric"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	healthEndpoint         = "/healthz"
	readinessEndpoint      = "/readyz"
	oauthDiscoveryEndpoint = "/.well-known/oauth-authorization-server"
	tokenEndpoint          = "/token"
	jwksEndpoint           = "/jwks"
)

// signingKeyCacheTTL keeps token signing off the database on every request.
const signingKeyCacheTTL = time.Minute

func authorizationServerRouter(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, clientStore oauth.ClientStore, metricsProvider *stsmetrics.Provider) (http.Handler, error) {
	e := &op.Endpoints{
		Token:   op.NewEndpoint(tokenEndpoint),
		JwksURI: op.NewEndpoint(jwksEndpoint),
	}

	keyStore := store.NewPostgresKeyStore(pool, signingKeyCacheTTL)
	if err := keyStore.EnsureSigningKey(ctx); err != nil {
		return nil, err
	}
	s, err := oauth.NewAuthorizationServer(ctx, cfg.AuthorizationServerConfig, clientStore, keyStore, metricsProvider.Metrics())
	if err != nil {
		return nil, err
	}

	router := chi.NewRouter()
	httpMetrics := otelchimetric.NewBaseConfig(
		"nais-sts",
		otelchimetric.WithMeterProvider(metricsProvider.MeterProvider()),
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
	router.Use(contextMiddleware(cfg.AuthorizationServerConfig.Issuer))
	router.HandleFunc(oauthDiscoveryEndpoint, oauth.DiscoveryEndpoint(e))
	router.HandleFunc(e.Token.Relative(), s.TokenEndpoint())
	router.HandleFunc(e.JwksURI.Relative(), s.JwksEndpoint())

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
