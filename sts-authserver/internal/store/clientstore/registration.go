package clientstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

func (s *Store) Save(ctx context.Context, client *oauth.Client, policies []oauth.AuthorizationPolicy, authoritativeIssuer string) error {
	if client.Issuer != authoritativeIssuer {
		return errRegistrationUnauthorized(client.ID, client.Issuer, authoritativeIssuer)
	}
	return database.WithTx(ctx, s.pool, func(ctx context.Context, queries *sqlgen.Queries) error {
		_, err := queries.UpsertClient(ctx, sqlgen.UpsertClientParams{
			ID:            client.ID,
			Environment:   client.Environment,
			Namespace:     client.Namespace,
			Name:          client.Name,
			Issuer:        client.Issuer,
			AllowedScopes: client.AllowedScopes,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := queries.GetClientByIDForUpdate(ctx, client.ID)
			if getErr != nil {
				return fmt.Errorf("get existing client: %w", getErr)
			}
			if existing.Issuer != authoritativeIssuer {
				return errRegistrationUnauthorized(client.ID, existing.Issuer, authoritativeIssuer)
			}
			return fmt.Errorf("%w: client %q", oauth.ErrImmutableFieldsChanged, client.ID)
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return fmt.Errorf("%w: %s: %v", oauth.ErrRegistrationConflict, clientKeyFromRow(client.Client), err)
		}
		if err != nil {
			return fmt.Errorf("upsert client: %w", err)
		}
		if err := queries.DeleteAuthorizationPolicies(ctx, client.ID); err != nil {
			return fmt.Errorf("delete authorization policies: %w", err)
		}

		for _, policy := range policies {
			if err := queries.UpsertAuthorizationPolicy(ctx, sqlgen.UpsertAuthorizationPolicyParams{
				OwnerClientID:    client.ID,
				ConsumerClientID: string(policy.Consumer),
				Roles:            policy.Roles,
			}); err != nil {
				return fmt.Errorf("upsert authorization policy: %w", err)
			}
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
