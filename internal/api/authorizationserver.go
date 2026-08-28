package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/config"
	http2 "github.com/nais/sts/internal/http"
	"github.com/nais/sts/internal/oauth"
	"github.com/riandyrn/otelchi"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/ready"
)

func authorizationServerRouter(ctx context.Context, cfg config.Config) (http.Handler, error) {
	e := &op.Endpoints{
		Token:   op.NewEndpoint("/token"),
		JwksURI: op.NewEndpoint("/jwks"),
	}

	s, err := oauth.NewAuthorizationServer(ctx, cfg)
	if err != nil {
		return nil, err
	}

	router := chi.NewRouter()
	router.Use(otelchi.Middleware(
		"nais-sts",
		otelchi.WithChiRoutes(router),
		otelchi.WithRequestMethodInSpanName(true),
		otelchi.WithFilter(func(r *http.Request) bool {
			return !strings.EqualFold(r.URL.Path, healthEndpoint) && !strings.EqualFold(r.URL.Path, readinessEndpoint)
		}),
	))
	router.Use(contextMiddleware(cfg.Issuer))
	router.HandleFunc(healthEndpoint, http2.RespondSuccess(op.Status{Status: "ok"}))
	router.HandleFunc(readinessEndpoint, http2.RespondSuccess(op.Status{Status: "ok"}))
	router.HandleFunc(oidc.DiscoveryEndpoint, oauth.DiscoveryEndpoint(e))
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
