package registration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/errs"
	http2 "github.com/nais/sts/internal/http"
	"github.com/nais/sts/internal/oauth"
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
	return http2.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if err := http2.RequireContentType(r, http2.MediaTypeJSON); err != nil {
			return err
		}

		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return errs.InvalidToken(err, "authentication failed")
		}

		registration, err := decodeClientRegistration(w, r)
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return errs.RequestTooLarge(err, "request body exceeds %d bytes", maxRegistrationBodySize)
			}
			return errs.InvalidClientMetadata(err, "invalid request body")
		}

		ss, err := registrator.VerifySoftwareStatement(r.Context(), registration.SoftwareStatement)
		if err != nil {
			return errs.InvalidSoftwareStatement(err, "software statement is invalid")
		}

		if err := a.SaveRegistration(r.Context(), registrator, ss); err != nil {
			return err
		}

		http2.WriteJSON(w, r, &ClientRegistrationResponse{
			ClientRegistration: registration,
			ClientID:           ss.ClientId,
		})
		return nil
	})
}

func (a *Api) DeleteEndpoint() http.HandlerFunc {
	return http2.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return errs.InvalidToken(err, "authentication failed")
		}

		clientID := oauth.ClientID(chi.URLParam(r, "id"))
		if err := clientID.Validate(); err != nil {
			return errs.InvalidRequest(err, "client ID is invalid")
		}

		err = a.store.Delete(r.Context(), clientID, registrator.AuthIssuer)
		if err != nil {
			if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
				return errs.UnauthorizedClient(err, "registrator is not authorized to delete client")
			}
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func (a *Api) SaveRegistration(ctx context.Context, registrator *Registrator, s *SoftwareStatement) error {
	if s.Workload.Issuer != registrator.AuthIssuer {
		return errs.UnapprovedSoftwareStatement(nil, "workload issuer %q does not match the registrator issuer %q", s.Workload.Issuer, registrator.AuthIssuer)
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
	switch {
	case err == nil:
		return nil
	case errors.Is(err, oauth.ErrRegistrationUnauthorized):
		return errs.UnauthorizedClient(err, "registrator is not authorized for client")
	case errors.Is(err, oauth.ErrImmutableFieldsChanged):
		return errs.InvalidClientMetadata(err, "registration conflicts with existing client: immutable fields cannot change")
	case errors.Is(err, oauth.ErrWorkloadTaken):
		return errs.InvalidClientMetadata(err, "workload is already registered to another client")
	default:
		return err
	}
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
