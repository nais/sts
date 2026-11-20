package clientstore

import (
	"fmt"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type clientSnapshot struct {
	clients     map[clientKey]sqlgen.Client
	policies    map[oauth.ClientID]policy
	clientsById map[oauth.ClientID]sqlgen.Client
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
