package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/sts/internal/oauth/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func NewClientAuthTokenVerifier(ctx context.Context, httpClient *http.Client, issuers []TokenIssuer) (*jwt.TokenVerifier, error) {
	opts := []jwt.TokenVerifierOption{
		jwt.WithClaimsVerifier(func(claims *oidc.AccessTokenClaims) error {
			return nil // TODO: fix
		}),
		jwt.WithHttpClient(httpClient),
	}

	for _, issuer := range issuers {
		opts = append(opts, jwt.WithIssuer(string(issuer)))
	}

	return jwt.NewTokenVerifier(ctx, opts...)
}

// TODO: lowercase or inline
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
