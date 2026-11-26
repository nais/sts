package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestVerifyClaimsExpiration(t *testing.T) {
	const issuer = "https://issuer.example"

	for _, tt := range []struct {
		name      string
		remaining time.Duration
		wantErr   error
	}{
		{name: "not expired", remaining: 10 * time.Second},
		{name: "expired within skew", remaining: -10 * time.Second},
		{name: "expired beyond skew", remaining: -time.Minute, wantErr: oidc.ErrExpired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			claims := new(AccessTokenClaims)
			claims.Issuer = issuer
			claims.IssuedAt = oidc.FromTime(now.Add(-time.Minute))
			claims.Expiration = oidc.FromTime(now.Add(tt.remaining))

			_, err := new(TokenVerifier).verifyClaims(issuerConfig{issuer: issuer}, claims)

			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
