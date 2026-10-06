package clientstore

import (
	"context"
	"fmt"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

type clientSnapshot struct {
	clients  map[clientKey]sqlgen.KubernetesClient
	policies map[policyKey]oauth.Roles
}

func loadClientSnapshot(ctx context.Context, queries *sqlgen.Queries) (*clientSnapshot, error) {
	clients, err := queries.ListKubernetesClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kubernetes clients: %w", err)
	}
	policies, err := queries.ListAuthorizationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list authorization policies: %w", err)
	}

	result := &clientSnapshot{
		clients:  make(map[clientKey]sqlgen.KubernetesClient, len(clients)),
		policies: make(map[policyKey]oauth.Roles, len(policies)),
	}
	for _, client := range clients {
		result.clients[clientKeyFromRow(client)] = client
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
	workload  string
}

func (k clientKey) String() string {
	return fmt.Sprintf("issuer %q, namespace %q, workload %q", k.issuer, k.namespace, k.workload)
}

func clientKeyFromRow(row sqlgen.KubernetesClient) clientKey {
	return clientKey{issuer: row.Issuer, namespace: row.Namespace, workload: row.Workload}
}

type policyKey struct {
	owner    string
	consumer string
}

func (k policyKey) String() string {
	return fmt.Sprintf("target %q, consumer %q", k.owner, k.consumer)
}

func toClient(row sqlgen.KubernetesClient) *oauth.Client {
	return &oauth.Client{KubernetesClient: row}
}
