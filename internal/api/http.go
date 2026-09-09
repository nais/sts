package api

import (
	"context"
	"fmt"
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
	registrationEndpoint   = "/registration/client"
)

func stsApi(
	ctx context.Context,
	cfg config.Config,
	clientStore oauth.ClientStore,
	keyStore oauth.KeyStore,
	provider *stsmetrics.Provider,
) (http.Handler, error) {
	e := &op.Endpoints{
		Token:   op.NewEndpoint(tokenEndpoint),
		JwksURI: op.NewEndpoint(jwksEndpoint),
	}

	router := chi.NewRouter()
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

	authServer, err := oauth.NewAuthorizationServer(ctx, cfg.AuthorizationServerConfig, clientStore, keyStore, provider.Metrics())
	if err != nil {
		return nil, fmt.Errorf("initialize authorization server: %w", err)
	}
	registrationApi, err := registration.NewApi(ctx, cfg.Registrators, cfg.AuthorizationServerConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize client registration handler: %w", err)
	}

	router.Get(oauthDiscoveryEndpoint, oauth.DiscoveryEndpoint(e, authServer.Issuer))
	router.Post(e.Token.Relative(), authServer.TokenEndpoint())
	router.Get(e.JwksURI.Relative(), authServer.JwksEndpoint())
	router.Post(registrationEndpoint, registrationApi.PostEndpoint())
	router.Delete(registrationEndpoint, registrationApi.DeleteEndpoint())
	return router, nil
}
