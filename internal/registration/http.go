package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Api struct {
	registrators *Registrators
	store        oauth.ClientStore
}

func NewApi(ctx context.Context, httpClient *http.Client, registrators ClientRegistrators, authServerCfg oauth.AuthorizationServerConfig, store oauth.ClientStore) (*Api, error) {
	registry, err := NewRegistrators(ctx, httpClient, authServerCfg, registrators...)
	if err != nil {
		return nil, err
	}
	return &Api{
		registrators: registry,
		store:        store,
	}, nil
}

func (a *Api) AuthenticateRequest(r *http.Request) (*Registrator, error) {
	return a.registrators.Authenticate(r)
}

func (a *Api) PostEndpoint() http.HandlerFunc {
	return oauth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if err := validateContentType(r); err != nil {
			return httpError(http.StatusUnsupportedMediaType, oidc.ErrInvalidRequest(), "content type must be application/json", err)
		}

		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return httpError(http.StatusUnauthorized, errInvalidToken(), "authentication failed", err)
		}

		registration, err := decodeClientRegistration(w, r)
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return httpError(http.StatusRequestEntityTooLarge, oidc.ErrInvalidRequest(), fmt.Sprintf("request body exceeds %d bytes", maxRegistrationBodySize), err)
			}
			return httpError(http.StatusBadRequest, errInvalidClientMetadata(), "invalid request body", err)
		}

		ss, err := registrator.VerifySoftwareStatement(r.Context(), registration.SoftwareStatement)
		if err != nil {
			return httpError(http.StatusBadRequest, errInvalidSoftwareStatement(), "software statement is invalid", err)
		}

		if err := a.SaveRegistration(r.Context(), registrator, ss); err != nil {
			if errors.Is(err, errIssuerMismatch) {
				return httpError(http.StatusBadRequest, errUnapprovedSoftwareStatement(), "workload issuer does not match the registrator issuer", err)
			}
			if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
				return httpError(http.StatusForbidden, oidc.ErrInvalidClient(), "registrator is not authorized for client", err)
			}
			if errors.Is(err, oauth.ErrImmutableFieldsChanged) {
				return httpError(http.StatusBadRequest, errInvalidClientMetadata(), "registration conflicts with existing client: immutable fields cannot change", err)
			}
			if errors.Is(err, oauth.ErrWorkloadTaken) {
				return httpError(http.StatusBadRequest, errInvalidClientMetadata(), "workload is already registered to another client", err)
			}
			return err
		}

		oauth.WriteJSON(w, r, &ClientRegistrationResponse{
			ClientRegistration: registration,
			ClientID:           ss.ClientId,
		})
		return nil
	})
}

func (a *Api) DeleteEndpoint() http.HandlerFunc {
	return oauth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return httpError(http.StatusUnauthorized, errInvalidToken(), "authentication failed", err)
		}

		clientID := oauth.ClientID(chi.URLParam(r, "id"))
		if err := clientID.Validate(); err != nil {
			return httpError(http.StatusBadRequest, oidc.ErrInvalidRequest(), "client ID is invalid", err)
		}

		err = a.store.Delete(r.Context(), clientID, registrator.AuthIssuer)
		if err != nil {
			if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
				return httpError(http.StatusForbidden, oidc.ErrInvalidClient(), "registrator is not authorized to delete client", err)
			}
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (a *Api) SaveRegistration(ctx context.Context, registrator *Registrator, s *SoftwareStatement) error {
	if s.Workload.Issuer != registrator.AuthIssuer {
		return fmt.Errorf("%w: workload issuer %q, registrator issuer %q", errIssuerMismatch, s.Workload.Issuer, registrator.AuthIssuer)
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

func validateContentType(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("got content type %q", r.Header.Get("Content-Type"))
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
