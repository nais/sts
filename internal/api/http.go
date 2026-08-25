package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/muhlemmer/gu"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/oauth"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/schema"
	"go.opentelemetry.io/otel"
)

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/ready"
)

var Tracer = otel.Tracer("github.com/nais/sts/internal/api")

type apiServer struct {
	router  *chi.Mux
	decoder httphelper.Decoder
	server  op.Server
}

func SetupAuthServerHandler(config config.Config) (http.Handler, error) {
	registrations, err := oauth.LoadRegistrationStore(config.RegistrationsFile)
	if err != nil {
		return nil, err
	}

	e := &op.Endpoints{
		Token:   op.NewEndpoint("/token"),
		JwksURI: op.NewEndpoint("/jwks"),
	}
	s, err := oauth.NewAuthServer(config.Issuer, e, registrations)
	if err != nil {
		return nil, err
	}

	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	ws := &apiServer{
		router:  chi.NewRouter(),
		decoder: decoder,
		server:  s,
	}

	ws.router.Use(contextMiddleware(config.Issuer))
	ws.router.HandleFunc(healthEndpoint, respondSuccess(op.Status{Status: "ok"}))
	ws.router.HandleFunc(readinessEndpoint, respondSuccess(op.Status{Status: "ok"}))
	ws.router.HandleFunc(oidc.DiscoveryEndpoint, discoveryEndpoint(e))
	ws.traceRoute(e.Token, ws.tokenEndpoint())
	ws.traceRoute(e.JwksURI, jwksEndpoint())

	return ws, nil
}

func (s *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *apiServer) traceRoute(e *op.Endpoint, hf http.HandlerFunc) {
	if e != nil {
		traceHandler := func(w http.ResponseWriter, r *http.Request) {
			ctx, span := Tracer.Start(r.Context(), e.Relative())
			r = r.WithContext(ctx)
			hf(w, r)
			defer span.End()
		}
		s.router.HandleFunc(e.Relative(), traceHandler)
		slog.Info("registered route", "endpoint", e.Relative())
	}
}

func contextMiddleware(issuer string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(op.ContextWithIssuer(r.Context(), issuer))
			next.ServeHTTP(w, r)
		})
	}
}

func respond(data any, err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			op.WriteError(w, r, err, nil)
			return
		}
		respondSuccess(data)(w, r)
	}
}

func respondSuccess(data any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, ok := data.(*op.Response)
		if !ok {
			resp = op.NewResponse(data)
		}
		gu.MapMerge(resp.Header, w.Header())
		httphelper.MarshalJSON(w, resp.Data)
	}
}

func decodeRequest[R any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*R, error) {
	dst := new(R)
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	form := r.Form
	if postOnly {
		form = r.PostForm
	}
	if err := decoder.Decode(dst, form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return dst, nil
}
