package clientstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

func (s *Store) Save(ctx context.Context, client *oauth.Client, authoritativeIssuer string) error {
	// TODO: should we allow "takeovers" (e.g. move a client from one issuer to another)
	if client.Issuer != authoritativeIssuer {
		return errRegistrationUnauthorized(string(client.ID), client.Issuer, authoritativeIssuer)
	}
	_, err := s.queries.UpsertClient(ctx, sqlgen.UpsertClientParams{
		ID:                  client.ID,
		Environment:         client.Environment,
		Namespace:           client.Namespace,
		Name:                client.Name,
		Issuer:              client.Issuer,
		AuthorizationPolicy: client.AuthorizationPolicy,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("upsert client: %w", err)
	}

	return nil
}

func (s *Store) Delete(ctx context.Context, clientID oauth.ClientID, authoritativeIssuer string) error {
	return database.WithTx(ctx, s.pool, func(ctx context.Context, queries *sqlgen.Queries) error {
		client, err := queries.GetClientByIDForUpdate(ctx, clientID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get client: %w", err)
		}

		if client.Issuer != authoritativeIssuer {
			return errRegistrationUnauthorized(string(clientID), client.Issuer, authoritativeIssuer)
		}

		if err := queries.DeleteClient(ctx, clientID); err != nil {
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
