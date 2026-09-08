package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/config"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
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

func authorizationServerRouter(authServer *oauth.AuthorizationServer, metricsProvider *stsmetrics.Provider) http.Handler {
	e := &op.Endpoints{
		Token:   op.NewEndpoint(tokenEndpoint),
		JwksURI: op.NewEndpoint(jwksEndpoint),
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
	router.HandleFunc(oauthDiscoveryEndpoint, oauth.DiscoveryEndpoint(e, authServer.Issuer))
	router.HandleFunc(e.Token.Relative(), authServer.TokenEndpoint())
	router.HandleFunc(e.JwksURI.Relative(), authServer.JwksEndpoint())

	return router
}

func registrationApiRouter(ctx context.Context, cfg config.Config, metricsProvider *stsmetrics.Provider) (http.Handler, error) {
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

	// TODO: actually add config here
	registrators := cfg.Registrators

	verifier, err := oauth.NewClientAuthTokenVerifier(ctx, cfg.AuthorizationServerConfig.ClientAuthIssuers)
	if err != nil {
		return nil, err
	}

	router.Handle("/registration/client", registration.NewClientHandler(registrators, verifier))
	return router, nil
}
