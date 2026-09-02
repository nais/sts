package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Client struct {
	queries *sqlgen.Queries
}

func NewClientStore(pool *pgxpool.Pool) *Client {
	return &Client{queries: sqlgen.New(pool)}
}

var _ oauth.ClientStore = (*Client)(nil)

func (s *Client) Get(ctx context.Context, clientAuthClaims *oauth.AccessTokenClaims) (*oauth.Client, error) {
	raw, ok := clientAuthClaims.Claims["kubernetes.io"]
	if !ok {
		return nil, oidc.ErrInvalidClient().WithDescription("missing kubernetes.io claims")
	}

	type kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	}
	var kc kubernetes
	err := json.Unmarshal(raw, &kc)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("invalid kubernetes.io claims: %+v", err)
	}

	row, err := s.queries.GetKubernetesClient(ctx, sqlgen.GetKubernetesClientParams{
		Issuer:    clientAuthClaims.Issuer,
		Namespace: kc.Namespace,
		Workload:  kc.ServiceAccount.Name,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrInvalidClient().WithDescription("client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("read client: %w", err)
	}
	return toClient(row), nil
}

func (s *Client) Save(ctx context.Context, client *oauth.Client) error {
	return s.queries.UpsertKubernetesClient(ctx, sqlgen.UpsertKubernetesClientParams{
		ID:            client.ID,
		Environment:   client.Environment,
		Namespace:     client.Namespace,
		Workload:      client.Workload,
		Issuer:        client.Issuer,
		AllowedScopes: client.AllowedScopes,
	})
}

// TODO: consider optimizing calls to db:
//   - move policy into client?
//   - cache in memory (update cache on insert/delete)?
//   - join on Get?
func (s *Client) AuthorizeTarget(ctx context.Context, clientID oauth.ClientID, target oauth.Target) (oauth.Roles, error) {
	row, err := s.queries.GetAuthorizationPolicy(ctx, sqlgen.GetAuthorizationPolicyParams{
		OwnerClientID:    string(clientID),
		ConsumerClientID: target.GetValue(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrInvalidClient().WithDescription("authorization policy not found")
	}
	if err != nil {
		return nil, oidc.ErrServerError().WithDescription("read authorization policy: %s", err)
	}
	return row.Roles, nil
}

func toClient(row sqlgen.KubernetesClient) *oauth.Client {
	return &oauth.Client{KubernetesClient: row}
}
