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

const (
	MediaTypeJSON = "application/json"
	MediaTypeForm = "application/x-www-form-urlencoded"
)

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
		if r.Header.Get("Accept") == MediaTypeJSON {
			contentType = MediaTypeJSON
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
			return NewErrorResponse(CodeInvalidRequest, "error parsing form").Wrap(err)
		}

		var request TokenRequest
		var err error

		switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
		case oidc.GrantTypeClientCredentials:
			request, err = decodeRequest[ClientCredentialsRequest](Decoder, r, true)
		case oidc.GrantTypeTokenExchange:
			if len(a.SubjectTokenIssuers) == 0 {
				return NewErrorResponse(CodeUnsupportedGrantType, "%s not supported", grantType)
			}
			request, err = decodeRequest[TokenExchangeRequest](Decoder, r, true)
		case "":
			return NewErrorResponse(CodeInvalidRequest, "grant_type missing")
		default:
			return NewErrorResponse(CodeUnsupportedGrantType, "%s not supported", grantType)
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

// WriteError writes err as an OAuth error response and logs it once.
// Any error that is not an ErrorResponse with a client code becomes 500 "internal error".
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	e, ok := clientErrorResponse(err)
	if !ok {
		e = NewErrorResponse(CodeServerError, "internal error").Wrap(err)
	}
	status := e.status()

	level := slog.LevelWarn
	if status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("code", e.Code),
		slog.String("description", e.Description),
		slog.Int("status_code", status),
	}
	if e.Cause != nil {
		attrs = append(attrs, slog.Any("error", e.Cause))
	}
	slog.LogAttrs(r.Context(), level, "request error", attrs...)

	w.Header().Set("Content-Type", MediaTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(e); err != nil {
		slog.ErrorContext(r.Context(), "encode error response", "error", err)
	}
}

func WriteJSON(w http.ResponseWriter, r *http.Request, v any) {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", MediaTypeJSON)
	}

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.ErrorContext(r.Context(), "encode response", "error", err)
	}
}

func decodeRequest[T any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*T, error) {
	dst := new(T)
	if err := r.ParseForm(); err != nil {
		return nil, NewErrorResponse(CodeInvalidRequest, "error parsing form").Wrap(err)
	}
	form := r.Form
	if postOnly {
		form = r.PostForm
	}
	if err := decoder.Decode(dst, form); err != nil {
		return nil, NewErrorResponse(CodeInvalidRequest, "error decoding form").Wrap(err)
	}
	return dst, nil
}
