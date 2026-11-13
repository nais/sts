package clientstore

import (
	"context"
	"fmt"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type clientSnapshot struct {
	clients  map[clientKey]sqlgen.Client
	policies map[oauth.ClientID]policy
}

// policy indexes a target's authorization policy for token requests.
type policy struct {
	clients    map[oauth.ClientID]oauth.Roles
	namespaces map[string]struct{}
	allowAll   bool
}

func newPolicy(p oauth.AuthorizationPolicy) policy {
	result := policy{
		clients:    make(map[oauth.ClientID]oauth.Roles, len(p.Clients)),
		namespaces: make(map[string]struct{}, len(p.AllowedNamespaces)),
		allowAll:   p.AllowAll,
	}
	for _, c := range p.Clients {
		result.clients[c.ClientID] = c.Roles
	}
	for _, namespace := range p.AllowedNamespaces {
		result.namespaces[namespace] = struct{}{}
	}
	return result
}

func loadClientSnapshot(ctx context.Context, queries *sqlgen.Queries) (*clientSnapshot, error) {
	clients, err := queries.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kubernetes clients: %w", err)
	}

	result := &clientSnapshot{
		clients:  make(map[clientKey]sqlgen.Client, len(clients)),
		policies: make(map[oauth.ClientID]policy, len(clients)),
	}
	for _, client := range clients {
		result.clients[clientKeyFromRow(client)] = client
		result.policies[client.ID] = newPolicy(client.AuthorizationPolicy)
	}
	return result, nil
}

type clientKey struct {
	issuer    string
	namespace string
	name      string
}

func (k clientKey) String() string {
	return fmt.Sprintf("issuer %q, namespace %q, name %q", k.issuer, k.namespace, k.name)
}

func clientKeyFromRow(row sqlgen.Client) clientKey {
	return clientKey{issuer: row.Issuer, namespace: row.Namespace, name: row.Name}
}

func toClient(row sqlgen.Client) *oauth.Client {
	return &oauth.Client{
		ID:                  row.ID,
		Issuer:              row.Issuer,
		Environment:         row.Environment,
		Namespace:           row.Namespace,
		Name:                row.Name,
		AuthorizationPolicy: row.AuthorizationPolicy,
		CreatedAt:           row.CreatedAt,
		UpdatedAt:           row.UpdatedAt,
	}
}
