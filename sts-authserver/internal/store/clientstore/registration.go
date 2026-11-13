package clientstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

func (s *Store) Save(ctx context.Context, client *oauth.Client, policies []oauth.AuthorizationPolicy, authoritativeIssuer string) error {
	// TODO: should we allow "takeovers" (e.g. move a client from one issuer to another)
	if client.Issuer != authoritativeIssuer {
		return errRegistrationUnauthorized(client.ID, client.Issuer, authoritativeIssuer)
	}
	return database.WithTx(ctx, s.pool, func(ctx context.Context, queries *sqlgen.Queries) error {
		_, err := queries.UpsertClient(ctx, sqlgen.UpsertClientParams{
			ID:                client.ID,
			Environment:       client.Environment,
			Namespace:         client.Namespace,
			Name:              client.Name,
			Issuer:            client.Issuer,
			AllowedScopes:     client.AllowedScopes,
			AllowAll:          client.AllowAll,
			AllowedNamespaces: client.AllowedNamespaces,
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("upsert client: %w", err)
		}

		existing, err := queries.ListAuthorizationPoliciesByOwner(ctx, client.ID)
		if err != nil {
			return fmt.Errorf("list existing authorization policies: %w", err)
		}
		orphaned := map[string]bool{}
		for _, p := range existing {
			if !slices.ContainsFunc(policies, func(policy oauth.AuthorizationPolicy) bool {
				return policy.Consumer == oauth.ClientID(p.ConsumerClientID)
			}) {
				orphaned[p.ConsumerClientID] = true
			}
		}
		orphanedIds := slices.Collect(maps.Keys(orphaned))

		if err := queries.DeleteOrphanedAuthorizationPolicies(ctx, sqlgen.DeleteOrphanedAuthorizationPoliciesParams{
			OwnerClientID: client.ID,
			OrphanedIds:   orphanedIds,
		}); err != nil {
			return fmt.Errorf("delete authorization policies: %w", err)
		}

		params := make([]sqlgen.BatchUpsertAuthorizationPolicyParams, 0)
		for _, policy := range policies {
			params = append(params, sqlgen.BatchUpsertAuthorizationPolicyParams{
				OwnerClientID:    client.ID,
				ConsumerClientID: string(policy.Consumer),
				Roles:            policy.Roles,
			})
		}

		var batchErr error
		queries.BatchUpsertAuthorizationPolicy(ctx, params).Exec(func(num int, err error) {
			if err != nil {
				batchErr = errors.Join(batchErr, err)
			}
		})

		if batchErr != nil {
			return fmt.Errorf("upsert authorization policy: %w", batchErr)
		}

		return nil
	})
}

func (s *Store) Delete(ctx context.Context, clientID oauth.ClientID, authoritativeIssuer string) error {
	return database.WithTx(ctx, s.pool, func(ctx context.Context, queries *sqlgen.Queries) error {
		client, err := queries.GetClientByIDForUpdate(ctx, string(clientID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get client: %w", err)
		}

		if client.Issuer != authoritativeIssuer {
			return errRegistrationUnauthorized(string(clientID), client.Issuer, authoritativeIssuer)
		}

		if err := queries.DeleteClient(ctx, string(clientID)); err != nil {
			return fmt.Errorf("delete client: %w", err)
		}
		return nil
	})
}

func errRegistrationUnauthorized(clientID, ownerIssuer, registratorIssuer string) error {
	return fmt.Errorf("%w: client %q, owner issuer %q, registrator issuer %q",
		oauth.ErrRegistrationUnauthorized,
		clientID,
		ownerIssuer,
		registratorIssuer,
	)
}
