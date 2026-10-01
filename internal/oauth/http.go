package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"reflect"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

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

const maxTokenRequestBodySize = 64 << 10

func (a *AuthorizationServer) TokenEndpoint() http.HandlerFunc {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		form, err := readTokenForm(w, r)
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

		WriteJSON(w, r, resp)
		return nil
	})
}

func readTokenForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if err := RequireContentType(r, MediaTypeForm); err != nil {
		return nil, err
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, RequestTooLarge(err, "request body exceeds %d bytes", maxTokenRequestBodySize)
		}
		return nil, InvalidRequest(err, "error parsing form")
	}
	return r.PostForm, nil
}

func (a *AuthorizationServer) parseTokenRequest(form url.Values) (TokenRequest, error) {
	switch grantType := oidc.GrantType(form.Get("grant_type")); grantType {
	case oidc.GrantTypeClientCredentials:
		return parseClientCredentialsRequest(form), nil
	case oidc.GrantTypeTokenExchange:
		if len(a.SubjectTokenIssuers) == 0 {
			return nil, UnsupportedGrantType(nil, "%s not supported", grantType)
		}
		return parseTokenExchangeRequest(form), nil
	case "":
		return nil, InvalidRequest(nil, "grant_type missing")
	default:
		return nil, UnsupportedGrantType(nil, "%s not supported", grantType)
	}
}

func RequireContentType(r *http.Request, mediaType string) error {
	header := r.Header.Get("Content-Type")
	got, _, err := mime.ParseMediaType(header)
	if err != nil || got != mediaType {
		return UnsupportedMediaType(fmt.Errorf("got content type %q", header), "content type must be %s", mediaType)
	}
	return nil
}

func HandlerFunc(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err == nil {
			return
		}
		e, ok := errors.AsType[*Error](err)
		if !ok {
			e = serverError(err)
		} else if err != error(e) {
			c := *e
			c.cause = err // log the context that f added around e
			e = &c
		}
		WriteError(w, r, e)
	}
}

func WriteError(w http.ResponseWriter, r *http.Request, e *Error) {
	level := slog.LevelWarn
	if e.status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("code", e.code),
		slog.String("description", e.description),
		slog.Int("status_code", e.status),
	}
	if e.cause != nil {
		attrs = append(attrs, slog.Any("error", e.cause))
	}
	slog.LogAttrs(r.Context(), level, "request error", attrs...)

	resp := e.HTTPError()
	w.Header().Set("Content-Type", MediaTypeJSON)
	w.WriteHeader(resp.Status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
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
