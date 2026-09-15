package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Api struct {
	registrators *Registrators
	store        oauth.ClientStore
}

func NewApi(ctx context.Context, registrators ClientRegistrators, authServerCfg oauth.AuthorizationServerConfig, store oauth.ClientStore) (*Api, error) {
	registry, err := NewRegistrators(ctx, authServerCfg, registrators...)
	if err != nil {
		return nil, err
	}
	return &Api{
		registrators: registry,
		store:        store,
	}, nil
}

func (a *Api) PostEndpoint() http.HandlerFunc {
	return errorAwareHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if err := validateContentType(r); err != nil {
			return withHTTPStatus(err, http.StatusUnsupportedMediaType)
		}

		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return withHTTPStatus(fmt.Errorf("unauthorized: %w", err), http.StatusUnauthorized)
		}

		registration, err := decodeClientRegistration(w, r)
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return withHTTPStatus(fmt.Errorf("request body too large"), http.StatusRequestEntityTooLarge)
			}
			return withHTTPStatus(fmt.Errorf("invalid request body"), http.StatusBadRequest)
		}
		ss, err := registrator.VerifySoftwareStatement(r.Context(), registration.SoftwareStatement)
		if err != nil {
			return withHTTPStatus(fmt.Errorf("invalid software statement: %w", err), http.StatusBadRequest)
		}

		if err := a.SaveRegistration(r.Context(), registrator, ss); err != nil {
			if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
				return withHTTPStatus(errors.New("registrator is not authorized for registration"), http.StatusForbidden)
			}
			if errors.Is(err, oauth.ErrRegistrationConflict) {
				return withHTTPStatus(oidc.ErrInvalidClient().WithDescription("registration conflicts with existing client"), http.StatusConflict)
			}
			// TODO: log error and return a generic error message to avoid leaking sensitive information
			return withHTTPStatus(fmt.Errorf("failed to save registration: %w", err), http.StatusInternalServerError)
		}

		respond(w, &ClientRegistrationResponse{
			ClientRegistration: registration,
		})
		return nil
	})
}

func (a *Api) DeleteEndpoint() http.HandlerFunc {
	return errorAwareHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return withHTTPStatus(fmt.Errorf("unauthorized: %w", err), http.StatusUnauthorized)
		}

		clientID := oauth.ClientID(chi.URLParam(r, "id"))
		if err := clientID.Validate(); err != nil {
			return withHTTPStatus(err, http.StatusBadRequest)
		}

		err = a.store.Delete(r.Context(), clientID, registrator.AuthIssuer)
		if err != nil {
			if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
				return withHTTPStatus(oidc.ErrInvalidClient().WithDescription("registrator is not authorized to delete client"), http.StatusForbidden)
			}
			return withHTTPStatus(fmt.Errorf("failed to delete registration: %w", err), http.StatusInternalServerError)
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (a *Api) AuthenticateRequest(r *http.Request) (*Registrator, error) {
	return a.registrators.Authenticate(r)
}

func (a *Api) SaveRegistration(ctx context.Context, registrator *Registrator, s *SoftwareStatement) error {
	if err := s.validate(); err != nil {
		return err
	}
	if s.Workload.Issuer != registrator.AuthIssuer {
		return oauth.ErrRegistrationUnauthorized
	}
	policies := make([]oauth.AuthorizationPolicy, len(s.AuthorizationPolicies))
	for i, policy := range s.AuthorizationPolicies {
		policies[i] = oauth.AuthorizationPolicy{
			Owner:    oauth.ClientID(s.ClientId),
			Consumer: oauth.ClientID(policy.Consumer),
			Roles:    oauth.Roles(policy.Roles),
		}
	}
	err := a.store.Save(ctx, &oauth.Client{
		ID:            s.ClientId,
		Environment:   s.Workload.Environment,
		Namespace:     s.Workload.Namespace,
		Workload:      s.Workload.Name,
		Issuer:        s.Workload.Issuer,
		AllowedScopes: []string{},
	}, policies, registrator.AuthIssuer)
	return err
}

func withHTTPStatus(err error, status int) error {
	return op.NewStatusError(err, status)
}

func errorAwareHandlerFunc(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			op.WriteError(w, r, err, slog.Default())
		}
	}
}

func validateContentType(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	return nil
}

const maxRegistrationBodySize = 64 << 10

func decodeClientRegistration(w http.ResponseWriter, r *http.Request) (ClientRegistration, error) {
	var registration ClientRegistration
	r.Body = http.MaxBytesReader(w, r.Body, maxRegistrationBodySize)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil {
		return registration, err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return registration, errors.New("request body must contain exactly one JSON value")
		}
		return registration, err
	}

	if err := registration.validate(); err != nil {
		return registration, err
	}
	return registration, nil
}

func respond(w http.ResponseWriter, resp any) {
	if resp == nil || (reflect.ValueOf(resp).Kind() == reflect.Pointer && reflect.ValueOf(resp).IsNil()) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", "application/json")
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
