package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type Client struct {
	queries *sqlgen.Queries
}

func NewClientStore(pool *pgxpool.Pool) *Client {
	return &Client{queries: sqlgen.New(pool)}
}

func (s *Client) Save(ctx context.Context, client *oauth.Client) error {
	_, err := s.queries.UpsertKubernetesClient(ctx, sqlgen.UpsertKubernetesClientParams{
		ID:            client.ID,
		Environment:   client.Environment,
		Namespace:     client.Namespace,
		Workload:      client.Workload,
		Issuer:        client.Issuer,
		AllowedScopes: client.AllowedScopes,
	})
	return err
}

type clientKey struct {
	issuer    string
	namespace string
	workload  string
}

func (k clientKey) String() string {
	return fmt.Sprintf("issuer %q, namespace %q, workload %q", k.issuer, k.namespace, k.workload)
}

func clientKeyFromRow(row sqlgen.KubernetesClient) clientKey {
	return clientKey{issuer: row.Issuer, namespace: row.Namespace, workload: row.Workload}
}

func toClient(row sqlgen.KubernetesClient) *oauth.Client {
	return &oauth.Client{KubernetesClient: row}
}
