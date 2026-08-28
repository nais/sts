package oauth

import (
	"context"
	"net/http"

	http2 "github.com/nais/sts/internal/http"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/schema"
)

var Decoder httphelper.Decoder

func init() {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	Decoder = decoder
}

func DiscoveryEndpoint(endpoints *op.Endpoints) func(http.ResponseWriter, *http.Request) {
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

func (a *AuthorizationServer) JwksEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := a.Keys(r.Context())
		http2.Respond(w, r, data, err)
	}
}

func (a *AuthorizationServer) TokenEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
			return
		}

		var data any
		var err error

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			data, err = a.clientCredentialsHandler(r)
		case oidc.GrantTypeTokenExchange:
			data, err = a.tokenExchangeHandler(r)
		case "":
			err = oidc.ErrInvalidRequest().WithDescription("grant_type missing")
		default:
			err = op.NewStatusError(
				oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType),
				http.StatusBadRequest,
			)
		}
		http2.Respond(w, r, data, err)
	}
}

func (a *AuthorizationServer) handleGrant[R any](r *http.Request, authorizationHandler func(context.Context, *R) (*op.Response, error)) (*op.Response, error) {
	request, err := decodeRequest[R](Decoder, r, true)
	if err != nil {
		return nil, err
	}
	return authorizationHandler(r.Context(), request)
}

func (a *AuthorizationServer) clientCredentialsHandler(r *http.Request) (*op.Response, error) {
	return a.handleGrant(r, a.ClientCredentialsExchange)
}

func (a *AuthorizationServer) tokenExchangeHandler(r *http.Request) (*op.Response, error) {
	return a.handleGrant(r, a.TokenExchange)
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
