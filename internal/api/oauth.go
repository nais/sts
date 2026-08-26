package api

import (
	"net/http"

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

func jwksEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: implement
	}
}

func (s *apiServer) tokenEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
			return
		}

		client, err := s.verifyClient(r)
		if err != nil {
			op.WriteError(w, r, err, nil)
			return
		}

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			respond(s.clientCredentialsHandler(r, client))(w, r)
		case oidc.GrantTypeTokenExchange:
			respond(s.tokenExchangeHandler(r, client))(w, r)
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

func (s *apiServer) verifyClient(r *http.Request) (op.Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	cc := new(op.ClientCredentials)
	if err := s.decoder.Decode(cc, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}

	if cc.ClientAssertion == "" || cc.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_assertion must be provided and be of type %s", oidc.ClientAssertionTypeJWTAssertion)
	}

	return s.server.VerifyClient(r.Context(), &op.Request[op.ClientCredentials]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   cc,
	})
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

func (s *apiServer) tokenExchangeHandler(r *http.Request, client op.Client) (*op.Response, error) {
	request, err := decodeRequest[oidc.TokenExchangeRequest](s.decoder, r, true)
	if err != nil {
		return nil, err
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
