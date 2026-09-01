package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type ClientStore struct {
	queries *sqlgen.Queries
}

func NewClientStore(pool *pgxpool.Pool) *ClientStore {
	return &ClientStore{queries: sqlgen.New(pool)}
}

var _ oauth.ClientStore = (*ClientStore)(nil)

func (s *ClientStore) GetClient(ctx context.Context, id oauth.ClientID) (*oauth.OAuthClient, error) {
	row, err := s.queries.GetKubernetesClient(ctx, string(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauth.ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read client: %w", err)
	}
	return toClient(row), nil
}

// TODO: implement
func (s *ClientStore) AuthorizeTarget(clientID oauth.ClientID, target oauth.ClientID) error {

	return nil
}

func toClient(row sqlgen.KubernetesClient) *oauth.OAuthClient {
	return &oauth.OAuthClient{KubernetesClient: row}
}

type MemoryClientStore struct {
	Clients map[oauth.ClientID]*oauth.OAuthClient
}

func (s *MemoryClientStore) GetClient(_ context.Context, id oauth.ClientID) (*oauth.OAuthClient, error) {
	client, ok := s.Clients[id]
	if !ok {
		return nil, oauth.ErrClientNotFound
	}
	return client, nil
}
