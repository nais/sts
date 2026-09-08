package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
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

func registrationApiRouter(metricsProvider *stsmetrics.Provider) http.Handler {
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
	router.Handle("/registration/client", registration.NewClientHandler(nil, nil))

	return router
}
