package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/muhlemmer/gu"
	"github.com/nais/sts/internal/config"
	"github.com/rs/cors"
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
	router    *chi.Mux
	handler   http.Handler
	endpoints *op.Endpoints
	decoder   httphelper.Decoder
	corsOpts  *cors.Options
	server    op.Server
}

func SetupEndpoints(config config.Config, authServer op.Server, endpoints *op.Endpoints, options ...ServerOption) http.Handler {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	ws := &apiServer{
		router:    chi.NewRouter(),
		endpoints: endpoints,
		decoder:   decoder,
		corsOpts:  &defaultCORSOptions,
		server:    authServer,
	}

	for _, option := range options {
		option(ws)
	}

	ws.createRouter()
	ws.router.Use(contextMiddleware(config.Issuer))
	ws.handler = ws.router
	if ws.corsOpts != nil {
		ws.handler = cors.New(*ws.corsOpts).Handler(ws.router)
	}
	return ws
}

func (s *apiServer) createRouter() {
	s.router.HandleFunc(healthEndpoint, respond(op.Status{Status: "ok"}))
	s.router.HandleFunc(readinessEndpoint, respond(op.Status{Status: "ok"}))
	s.router.HandleFunc(oidc.DiscoveryEndpoint, discoveryEndpoint(s.endpoints))
	s.traceRoute(s.endpoints.Token, s.tokenEndpoint())
	s.traceRoute(s.endpoints.JwksURI, jwksEndpoint())
}

func contextMiddleware(issuer string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(op.ContextWithIssuer(r.Context(), issuer))
			next.ServeHTTP(w, r)
		})
	}
}

func jwksEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func (s *apiServer) tokenEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
			return
		}
		client, ok := r.Context().Value(clientCtxKey).(op.Client)
		if !ok {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("client not found").WithParent(nil), nil)
		}

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			resp, err := s.clientCredentialsHandler(r, client)
			if err != nil {
				op.WriteError(w, r, err, nil)
				return
			}
			respond(resp)(w, r)
		case oidc.GrantTypeTokenExchange:
			resp, err := s.tokenExchangeHandler(r, client)
			if err != nil {
				op.WriteError(w, r, err, nil)
				return
			}
			respond(resp)(w, r)
		case "":
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), nil)
		default:
			err := oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType)
			status := op.NewStatusError(err, http.StatusBadRequest) // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
			op.WriteError(w, r, status, nil)
		}
	}
}

func discoveryEndpoint(endpoints *op.Endpoints) func(http.ResponseWriter, *http.Request) {
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

func (s *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

type ServerOption func(s *apiServer)

const clientCtxKey int = iota

func (s *apiServer) withClientAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ca, err := parseClientAssertion(r, s.decoder)
			if err != nil {
				op.WriteError(w, r, err, nil)
				return
			}
			client, err := s.verifyClient(r, ca)
			if err != nil {
				op.WriteError(w, r, err, nil)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), clientCtxKey, client))
			next.ServeHTTP(w, r)
		})
	}
}

func (s *apiServer) verifyClient(r *http.Request, cc *op.ClientCredentials) (_ op.Client, err error) {
	return s.server.VerifyClient(r.Context(), &op.Request[op.ClientCredentials]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   cc,
	})
}

func parseClientAssertion(r *http.Request, decoder httphelper.Decoder) (_ *op.ClientCredentials, err error) {
	if err = r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	cc := new(op.ClientCredentials)
	if err = decoder.Decode(cc, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	if cc.ClientAssertion == "" || cc.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_assertion must be provided and be of type %s", oidc.ClientAssertionTypeJWTAssertion)
	}
	return cc, nil
}

func (s *apiServer) tokenExchangeHandler(r *http.Request, client op.Client) (*op.Response, error) {
	request, err := decodeRequest[oidc.TokenExchangeRequest](s.decoder, r, true)
	if err != nil {
		return nil, err
	}
	if request.SubjectToken == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token missing")

	}
	if request.SubjectTokenType == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type missing")

	}
	if !request.SubjectTokenType.IsSupported() {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type is not supported")

	}
	if request.RequestedTokenType != "" && !request.RequestedTokenType.IsSupported() {
		return nil, oidc.ErrInvalidRequest().WithDescription("requested_token_type is not supported")
	}
	resp, err := s.server.TokenExchange(r.Context(), &op.ClientRequest[oidc.TokenExchangeRequest]{
		Request: &op.Request[oidc.TokenExchangeRequest]{
			Method:   r.Method,
			URL:      r.URL,
			Header:   r.Header,
			Form:     r.Form,
			PostForm: r.PostForm,
			Data:     request,
		},
		Client: client,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *apiServer) clientCredentialsHandler(r *http.Request, client op.Client) (*op.Response, error) {
	request, err := decodeRequest[oidc.ClientCredentialsRequest](s.decoder, r, true)
	if err != nil {
		return nil, err
	}
	resp, err := s.server.ClientCredentialsExchange(r.Context(), &op.ClientRequest[oidc.ClientCredentialsRequest]{
		Request: &op.Request[oidc.ClientCredentialsRequest]{
			Method:   r.Method,
			URL:      r.URL,
			Header:   r.Header,
			Form:     r.Form,
			PostForm: r.PostForm,
			Data:     request,
		},
		Client: client,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func respond(data any) http.HandlerFunc {
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

// WithHTTPMiddleware sets the passed middleware chain to the root of
// the Server's router.
func WithHTTPMiddleware(m ...func(http.Handler) http.Handler) ServerOption {
	return func(s *apiServer) {
		s.router.Use(m...)
	}
}

// WithSetRouter allows customization or the Server's router.
func WithSetRouter(set func(chi.Router)) ServerOption {
	return func(s *apiServer) {
		set(s.router)
	}
}

// WithDecoder overrides the default decoder,
// which is a [schema.Decoder] with IgnoreUnknownKeys set to true.
func WithDecoder(decoder httphelper.Decoder) ServerOption {
	return func(s *apiServer) {
		s.decoder = decoder
	}
}

// WithServerCORSOptions sets the CORS policy for the Server's router.
func WithServerCORSOptions(opts *cors.Options) ServerOption {
	return func(s *apiServer) {
		s.corsOpts = opts
	}
}
