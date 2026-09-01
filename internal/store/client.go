package store

import (
	"context"
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

func (s *Client) Get(ctx context.Context, id oauth.ClientID) (*oauth.Client, error) {
	row, err := s.queries.GetKubernetesClient(ctx, string(id))
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
		Issuers:       client.Issuers,
		AllowedScopes: client.AllowedScopes,
	})
}

// TODO: consider optimizing calls to db:
//   - move policy into client?
//   - cache in memory (update cache on insert/delete)?
//   - join on Get?
func (s *Client) AuthorizeTarget(ctx context.Context, clientID oauth.ClientID, target oauth.Target) error {
	_, err := s.queries.GetAuthorizationPolicy(ctx, sqlgen.GetAuthorizationPolicyParams{
		OwnerClientID:    string(clientID),
		ConsumerClientID: target.GetValue(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.ErrInvalidClient().WithDescription("authorization policy not found")
	}
	if err != nil {
		return fmt.Errorf("read authorization policy: %w", err)
	}
	// TODO: return roles
	return nil
}

func toClient(row sqlgen.KubernetesClient) *oauth.Client {
	return &oauth.Client{KubernetesClient: row}
}
