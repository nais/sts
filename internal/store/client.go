package store

import (
	"context"
	"encoding/json"

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

type clientKey struct {
	issuer    string
	namespace string
	workload  string
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

func clientKeyFromClaims(claims *oauth.AccessTokenClaims) (clientKey, error) {
	raw, ok := claims.Claims["kubernetes.io"]
	if !ok {
		return clientKey{}, oidc.ErrInvalidClient().WithDescription("missing kubernetes.io claims")
	}

	type kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	}
	var kc kubernetes
	if err := json.Unmarshal(raw, &kc); err != nil {
		return clientKey{}, oidc.ErrInvalidClient().WithDescription("invalid kubernetes.io claims: %+v", err)
	}
	return clientKey{
		issuer:    claims.Issuer,
		namespace: kc.Namespace,
		workload:  kc.ServiceAccount.Name,
	}, nil
}

func toClient(row sqlgen.KubernetesClient) *oauth.Client {
	return &oauth.Client{KubernetesClient: row}
}
