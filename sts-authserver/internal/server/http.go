package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/config"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/riandyrn/otelchi"
	otelchimetric "github.com/riandyrn/otelchi/metric"
)

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/readyz"
)

func stsApi(
	ctx context.Context,
	cfg config.Config,
	clientStore oauth.ClientStore,
	keyStore oauth.KeyStore,
	provider *stsmetrics.Provider,
) (http.Handler, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirect to %q is not allowed", req.URL)
		},
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

	authServer, err := oauth.NewAuthorizationServer(ctx, httpClient, cfg.AuthorizationServerConfig, clientStore, keyStore, provider.Metrics())
	if err != nil {
		return nil, fmt.Errorf("initialize authorization server: %w", err)
	}
	registrationApi, err := registration.NewApi(ctx, httpClient, cfg.Registrators, cfg.AuthorizationServerConfig, clientStore)
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
