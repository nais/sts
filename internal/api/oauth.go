package api

import (
	"net/http"

	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

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

func (s *apiServer) jwksEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respond(s.server.Keys(r.Context()))(w, r)
	}
}

func (s *apiServer) tokenEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
			return
		}

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			respond(s.clientCredentialsHandler(r))(w, r)
		case oidc.GrantTypeTokenExchange:
			respond(s.tokenExchangeHandler(r))(w, r)
		case "":
			respond(nil, oidc.ErrInvalidRequest().WithDescription("grant_type missing"))(w, r)
		default:
			respond(nil,
				op.NewStatusError(
					oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType),
					http.StatusBadRequest,
				),
			)(w, r)
		}
	}
}

func (s *apiServer) clientCredentialsHandler(r *http.Request) (*op.Response, error) {
	request, err := decodeRequest[oauth.ClientCredentialsRequest](s.decoder, r, true)
	if err != nil {
		return nil, err
	}
	resp, err := s.server.ClientCredentialsExchange(r.Context(), request)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *apiServer) tokenExchangeHandler(r *http.Request) (*op.Response, error) {
	request, err := decodeRequest[oauth.TokenExchangeRequest](s.decoder, r, true)
	if err != nil {
		return nil, err
	}
	resp, err := s.server.TokenExchange(r.Context(), request)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
