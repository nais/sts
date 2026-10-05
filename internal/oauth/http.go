package oauth

import (
	nethttp "net/http"
	"net/url"

	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func DiscoveryEndpoint(endpoints *op.Endpoints, cfg AuthorizationServerConfig) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		grantTypes := []oidc.GrantType{oidc.GrantTypeClientCredentials}
		if len(cfg.SubjectTokenIssuers) > 0 {
			grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
		}

		i := string(cfg.Issuer)
		http.WriteJSON(w, r, &oidc.DiscoveryConfiguration{
			Issuer:              i,
			TokenEndpoint:       endpoints.Token.Absolute(i),
			JwksURI:             endpoints.JwksURI.Absolute(i),
			GrantTypesSupported: grantTypes,
			TokenEndpointAuthMethodsSupported: []oidc.AuthMethod{
				oidc.AuthMethodPrivateKeyJWT,
			},
			TokenEndpointAuthSigningAlgValuesSupported: cfg.ClientAuthSigningAlgorithms,
		})
	}
}

func (a *AuthorizationServer) JwksEndpoint() nethttp.HandlerFunc {
	return http.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
		contentType := "application/jwk-set+json"
		if r.Header.Get("Accept") == http.MediaTypeJSON {
			contentType = http.MediaTypeJSON
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Add("Vary", "Accept")

		resp, err := a.Keys(r.Context())
		if err != nil {
			return err
		}

		http.WriteJSON(w, r, resp)
		return nil
	})
}

func (a *AuthorizationServer) TokenEndpoint() nethttp.HandlerFunc {
	return http.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
		form, err := http.ReadForm(w, r)
		if err != nil {
			return err
		}

		request, err := a.parseTokenRequest(form)
		if err != nil {
			return err
		}

		resp, err := a.GrantHandler(r.Context(), request)
		if err != nil {
			return err
		}

		http.WriteJSON(w, r, resp)
		return nil
	})
}

func (a *AuthorizationServer) parseTokenRequest(form url.Values) (TokenRequest, error) {
	switch grantType := oidc.GrantType(form.Get("grant_type")); grantType {
	case oidc.GrantTypeClientCredentials:
		return parseClientCredentialsRequest(form), nil
	case oidc.GrantTypeTokenExchange:
		if len(a.SubjectTokenIssuers) == 0 {
			return nil, errs.UnsupportedGrantType(nil, "%s not supported", grantType)
		}
		return parseTokenExchangeRequest(form), nil
	case "":
		return nil, errs.InvalidRequest(nil, "grant_type missing")
	default:
		return nil, errs.UnsupportedGrantType(nil, "%s not supported", grantType)
	}
}
