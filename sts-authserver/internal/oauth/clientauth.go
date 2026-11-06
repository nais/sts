package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/sts/internal/jwt"
)

func NewClientAuthTokenVerifier(ctx context.Context, httpClient *http.Client, issuers []TokenIssuer, expectedAudience string, maxLifetime time.Duration) (*jwt.TokenVerifier, error) {
	opts := []jwt.TokenVerifierOption{
		jwt.WithClaimsVerifier(func(claims *jwt.AccessTokenClaims) error {
			// TODO: should be an option within verifier
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
			// TODO: this should be checked in the verifier
			if !expiration.After(issuedAt) {
				return errors.New("expiration must be after issued-at")
			}
			// TODO: maxage should be configured and checked via verifier
			if claims.Expiration.AsTime().Sub(issuedAt) > maxLifetime+time.Minute {
				return fmt.Errorf("token lifetime %s exceeds maximum %s", expiration.Sub(issuedAt), maxLifetime)
			}
			return nil
		}),
		jwt.WithHttpClient(httpClient),
	}

	for _, issuer := range issuers {
		opts = append(opts, jwt.WithIssuer(string(issuer)))
	}

	return jwt.NewTokenVerifier(ctx, opts...)
}
