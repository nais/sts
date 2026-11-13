package registration

import (
	"context"
	"errors"
	"log/slog"
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

func NewApi(ctx context.Context, httpClient *nethttp.Client, authServerCfg oauth.AuthorizationServerConfig, store oauth.ClientStore) (*Api, error) {
	registry, err := NewRegistrators(ctx, httpClient, authServerCfg)
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

		clientID, err := a.SaveRegistration(r.Context(), registrator, ss)
		if err != nil {
			return err
		}

		slog.InfoContext(r.Context(), "client registered",
			slog.String("client_id", string(clientID)),
			slog.String("registrator_issuer", registrator.AuthIssuer),
		)

		http.WriteJSON(w, r, &api.ClientRegistrationResponse{
			ClientRegistration: *registration,
			ClientID:           string(clientID),
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

		slog.InfoContext(r.Context(), "client deleted",
			slog.String("client_id", string(clientID)),
			slog.String("registrator_issuer", registrator.AuthIssuer),
		)

		w.WriteHeader(nethttp.StatusNoContent)

		return nil
	})
}

// SaveRegistration stores the client in the registrator's environment and
// returns its client ID. Each policy authorizes the consumer namespace and name
// in every configured environment, including consumers not registered yet.
func (a *Api) SaveRegistration(ctx context.Context, registrator *Registrator, s *SoftwareStatement) (oauth.ClientID, error) {
	clientID := oauth.NewClientID(registrator.Environment, oauth.Name(s.Client.Namespace), oauth.Name(s.Client.Name))

	policy := oauth.AuthorizationPolicy{
		AllowAll:          s.AuthorizationPolicy.AllowAll,
		AllowedNamespaces: s.AuthorizationPolicy.AllowedNamespaces,
		Clients:           make([]oauth.AuthorizedClient, 0),
	}
	for _, c := range s.AuthorizationPolicy.Clients {
		for _, environment := range a.registrators.environments {
			policy.Clients = append(policy.Clients, oauth.AuthorizedClient{
				ClientID: oauth.NewClientID(environment, oauth.Name(c.Namespace), oauth.Name(c.Name)),
				Roles:    c.Roles,
			})
		}
	}

	err := a.store.Save(ctx, &oauth.Client{
		ID:                  clientID,
		Environment:         string(registrator.Environment),
		Namespace:           s.Client.Namespace,
		Name:                s.Client.Name,
		Issuer:              registrator.AuthIssuer,
		AuthorizationPolicy: policy,
	}, registrator.AuthIssuer)
	if err != nil {
		if errors.Is(err, oauth.ErrRegistrationUnauthorized) {
			return "", errs.UnauthorizedClient(err, "registrator is not authorized for client")
		}
		return "", err
	}

	return clientID, nil
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
