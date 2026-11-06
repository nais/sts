package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func NewClientAuthTokenVerifier(ctx context.Context, httpClient *http.Client, issuers []TokenIssuer) (MultiIssuerTokenVerifier, error) {
	clientAuthVerifiers, err := ExternalTokenVerifiers(ctx, httpClient, issuers...)
	if err != nil {
		return nil, fmt.Errorf("resolving client auth verifiers: %w", err)
	}
	return NewMultiIssuerTokenVerifier(clientAuthVerifiers...)
}

func ValidateClientAuthClaims(claims *AccessTokenClaims, expectedAudience string, maxLifetime time.Duration) error {
	if len(claims.Audience) != 1 || claims.Audience[0] != expectedAudience {
		return fmt.Errorf("audience %q is invalid, expected %q", claims.Audience, expectedAudience)
	}
	issuedAt := claims.IssuedAt.AsTime()
	if issuedAt.IsZero() {
		return errors.New("issued at claim is missing")
	}
	expiration := claims.Expiration.AsTime()
	if expiration.IsZero() {
		return errors.New("expiration claim is missing")
	}
	if !expiration.After(issuedAt) {
		return errors.New("expiration must be after issued-at")
	}
	if expiration.Sub(issuedAt) > maxLifetime+time.Minute {
		return fmt.Errorf("token lifetime %s exceeds maximum %s", expiration.Sub(issuedAt), maxLifetime)
	}
	return nil
}
