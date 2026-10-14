package registration

import (
	"context"
	"errors"
	nethttp "net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/http"
	"github.com/nais/sts/internal/oauth"
)

type Api struct {
	registrators *Registrators
	store        oauth.ClientStore
}

func NewApi(ctx context.Context, httpClient *nethttp.Client, registrators ClientRegistrators, authServerCfg oauth.AuthorizationServerConfig, store oauth.ClientStore) (*Api, error) {
	registry, err := NewRegistrators(ctx, httpClient, authServerCfg, registrators...)
	if err != nil {
		return nil, err
	}
	return &Api{
		registrators: registry,
		store:        store,
	}, nil
}

func (a *Api) AuthenticateRequest(r *nethttp.Request) (*Registrator, error) {
	return a.registrators.Authenticate(r)
}

func (a *Api) PostEndpoint() nethttp.HandlerFunc {
	return http.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
		if err := http.RequireContentType(r, http.MediaTypeJSON); err != nil {
			return err
		}

		registrator, err := a.AuthenticateRequest(r)
		if err != nil {
			return errs.InvalidToken(err, "authentication failed")
		}

		registration, err := decodeClientRegistration(w, r)
		if err != nil {
			return err
		}

		ss, err := registrator.VerifySoftwareStatement(r.Context(), registration.SoftwareStatement)
		if err != nil {
			return errs.InvalidSoftwareStatement(err, "software statement is invalid")
		}

		if err := a.SaveRegistration(r.Context(), registrator, ss); err != nil {
			return err
		}

		http.WriteJSON(w, r, &api.ClientRegistrationResponse{
			ClientRegistration: *registration,
			ClientID:           ss.ClientID,
		})
		return nil
	})
}

func (a *Api) DeleteEndpoint() nethttp.HandlerFunc {
	return http.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
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

		w.WriteHeader(nethttp.StatusNoContent)
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
			Owner:    oauth.ClientID(s.ClientID),
			Consumer: oauth.ClientID(policy.Consumer),
			Roles:    policy.Roles,
		}
	}
	err := a.store.Save(ctx, &oauth.Client{
		ID:            s.ClientID,
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
	case errors.Is(err, oauth.ErrRegistrationConflict):
		return errs.InvalidClientMetadata(err, "workload is already registered to another client")
	default:
		return err
	}
}

func decodeClientRegistration(w nethttp.ResponseWriter, r *nethttp.Request) (*api.ClientRegistration, error) {
	obj, err := http.ReadJSON[api.ClientRegistration](w, r)
	if err != nil {
		if _, ok := errors.AsType[*nethttp.MaxBytesError](err); ok {
			return nil, errs.InvalidRequest(err, "invalid request body")
		}
		return nil, errs.InvalidClientMetadata(err, "invalid request body")
	}

	if strings.TrimSpace(obj.SoftwareStatement) == "" {
		return nil, errs.InvalidClientMetadata(err, "software_statement is required")
	}
	if len(obj.SoftwareStatement) > maxSoftwareStatementLength {
		return nil, errs.InvalidClientMetadata(nil, "software_statement is too long")
	}
	return &obj, nil
}
