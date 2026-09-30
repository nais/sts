package oauth

import (
	"encoding/json"
	"log/slog"
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
		grantTypes := []oidc.GrantType{oidc.GrantTypeClientCredentials}
		if len(cfg.SubjectTokenIssuers) > 0 {
			grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
		}

		i := string(cfg.Issuer)
		WriteJSON(w, r, &oidc.DiscoveryConfiguration{
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

func (a *AuthorizationServer) JwksEndpoint() http.HandlerFunc {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		contentType := "application/jwk-set+json"
		if r.Header.Get("Accept") == "application/json" {
			contentType = "application/json"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Add("Vary", "Accept")

		resp, err := a.Keys(r.Context())
		if err != nil {
			return err
		}

		WriteJSON(w, r, resp)
		return nil
	})
}

func (a *AuthorizationServer) TokenEndpoint() http.HandlerFunc {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if err := r.ParseForm(); err != nil {
			return WrapError(oidc.ErrInvalidRequest(), "error parsing form", err)
		}

		var request TokenRequest
		var err error

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			request, err = decodeRequest[ClientCredentialsRequest](Decoder, r, true)
		case oidc.GrantTypeTokenExchange:
			if len(a.SubjectTokenIssuers) == 0 {
				return oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType)
			}
			request, err = decodeRequest[TokenExchangeRequest](Decoder, r, true)
		case "":
			return oidc.ErrInvalidRequest().WithDescription("grant_type missing")
		default:
			return oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType)
		}
		if err != nil {
			return err
		}

		resp, err := a.GrantHandler(r.Context(), request)
		if err != nil {
			return err
		}

		WriteJSON(w, r, resp)
		return nil
	})
}

// HandlerFunc writes errors returned by f as OAuth error responses.
func HandlerFunc(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteError(w, r, err)
		}
	}
}

// WriteError writes err as an OAuth error response.
// Errors without a reason that is safe to show become 500 "internal error".
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	if _, ok := clientError(err); !ok {
		err = WrapError(oidc.ErrServerError(), "internal error", err)
	}
	op.WriteError(w, r, err, nil)
}

func WriteJSON(w http.ResponseWriter, r *http.Request, v any) {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", "application/json")
	}

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.ErrorContext(r.Context(), "encode response", "error", err)
	}
}

func decodeRequest[T any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*T, error) {
	dst := new(T)
	if err := r.ParseForm(); err != nil {
		return nil, WrapError(oidc.ErrInvalidRequest(), "error parsing form", err)
	}
	form := r.Form
	if postOnly {
		form = r.PostForm
	}
	if err := decoder.Decode(dst, form); err != nil {
		return nil, WrapError(oidc.ErrInvalidRequest(), "error decoding form", err)
	}
	return dst, nil
}
