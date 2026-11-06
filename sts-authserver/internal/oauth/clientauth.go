package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/nais/sts/internal/jwt"
)

func NewClientAuthTokenVerifier(ctx context.Context, httpClient *http.Client, issuers []jwt.Issuer, expectedAudience string, maxLifetime time.Duration) (*jwt.TokenVerifier, error) {
	opts := []jwt.TokenVerifierOption{
		jwt.WithHttpClient(httpClient),
		jwt.WithExpectedAudience(expectedAudience),
		jwt.WithMaxTokenLifetime(maxLifetime),
	}

	for _, issuer := range issuers {
		opts = append(opts, jwt.WithIssuer(issuer))
	}

	return jwt.NewTokenVerifier(ctx, opts...)
}
