package clientstore

import (
	"context"
	"fmt"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type clientSnapshot struct {
	clients  map[clientKey]sqlgen.Client
	policies map[policyKey]oauth.Roles
	// namespacePolicies holds owner IDs paired with authorized consumer namespaces.
	namespacePolicies map[namespacePolicyKey]struct{}
	// allowAllOwners holds IDs of clients that authorize every consumer.
	allowAllOwners map[string]struct{}
}

func loadClientSnapshot(ctx context.Context, queries *sqlgen.Queries) (*clientSnapshot, error) {
	clients, err := queries.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kubernetes clients: %w", err)
	}
	policies, err := queries.ListAuthorizationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list authorization policies: %w", err)
	}

	result := &clientSnapshot{
		clients:  make(map[clientKey]sqlgen.Client, len(clients)),
		policies: make(map[policyKey]oauth.Roles, len(policies)),

		namespacePolicies: make(map[namespacePolicyKey]struct{}),
		allowAllOwners:    make(map[string]struct{}),
	}
	for _, client := range clients {
		result.clients[clientKeyFromRow(client)] = client
		if client.AllowAllConsumers {
			result.allowAllOwners[client.ID] = struct{}{}
		}
		for _, namespace := range client.AllowedConsumerNamespaces {
			result.namespacePolicies[namespacePolicyKey{owner: client.ID, namespace: namespace}] = struct{}{}
		}
	}

	for _, policy := range policies {
		result.policies[policyKey{
			owner:    policy.OwnerClientID,
			consumer: policy.ConsumerClientID,
		}] = policy.Roles
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

type policyKey struct {
	owner    string
	consumer string
}

func (k policyKey) String() string {
	return fmt.Sprintf("target %q, consumer %q", k.owner, k.consumer)
}

type namespacePolicyKey struct {
	owner     string
	namespace string
}

func toClient(row sqlgen.Client) *oauth.Client {
	return &oauth.Client{Client: row}
}
