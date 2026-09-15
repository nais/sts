package oauth

import (
	"encoding/json"
	"net/http"
	"reflect"

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

func DiscoveryEndpoint(endpoints *op.Endpoints, cfg AuthorizationServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i := string(cfg.Issuer)
		grantTypes := []oidc.GrantType{oidc.GrantTypeClientCredentials}
		if len(cfg.SubjectTokenIssuers) > 0 {
			grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
		}
		respond(w, r, &Response{
			Data: &oidc.DiscoveryConfiguration{
				Issuer:              i,
				TokenEndpoint:       endpoints.Token.Absolute(i),
				JwksURI:             endpoints.JwksURI.Absolute(i),
				GrantTypesSupported: grantTypes,
				TokenEndpointAuthMethodsSupported: []oidc.AuthMethod{
					oidc.AuthMethodPrivateKeyJWT,
				},
				TokenEndpointAuthSigningAlgValuesSupported: cfg.ClientAuthSigningAlgorithms,
			},
		}, nil)
	}
}

func (a *AuthorizationServer) JwksEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		contentType := "application/jwk-set+json"
		if r.Header.Get("Accept") == "application/json" {
			contentType = "application/json"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Add("Vary", "Accept")

		resp, err := a.Keys(r.Context())
		respond(w, r, resp, err)
	}
}

func (a *AuthorizationServer) TokenEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			op.WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
			return
		}

		var resp *Response
		var err error
		var request TokenRequest

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			request, err = decodeRequest[ClientCredentialsRequest](Decoder, r, true)
		case oidc.GrantTypeTokenExchange:
			if len(a.SubjectTokenIssuers) == 0 {
				err = op.NewStatusError(
					oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType),
					http.StatusBadRequest,
				)
			} else {
				request, err = decodeRequest[TokenExchangeRequest](Decoder, r, true)
			}
		case "":
			err = oidc.ErrInvalidRequest().WithDescription("grant_type missing")
		default:
			err = op.NewStatusError(
				oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType),
				http.StatusBadRequest,
			)
		}
		if err == nil {
			resp, err = a.GrantHandler(r.Context(), request)
		}
		respond(w, r, resp, err)
	}
}

type Response struct {
	Data any
}

func respond(w http.ResponseWriter, r *http.Request, resp *Response, err error) {
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}

	if resp.Data == nil || (reflect.ValueOf(resp.Data).Kind() == reflect.Pointer && reflect.ValueOf(resp.Data).IsNil()) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", "application/json")
	}

	if err := json.NewEncoder(w).Encode(resp.Data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func decodeRequest[T any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*T, error) {
	dst := new(T)
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
