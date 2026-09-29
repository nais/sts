package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestVerifyTokenExchangeClaimsRejectsMalformedActor(t *testing.T) {
	server := &AuthorizationServer{}
	err := server.verifyTokenExchangeClaims(&AccessTokenClaims{
		Claims: map[string]json.RawMessage{"act": json.RawMessage(`"invalid"`)},
	}, "client")
	require.ErrorContains(t, err, "act claim is invalid")
}

func TestValidateClientAuthClaimsLifetime(t *testing.T) {
	now := time.Now().Round(time.Second)
	claims := &AccessTokenClaims{
		Audience:   oidc.Audience{"expected"},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(time.Hour + time.Minute))}
	require.NoError(t, ValidateClientAuthClaims(claims, "expected", time.Hour))

	claims.Expiration = oidc.FromTime(now.Add(time.Hour + time.Minute + time.Second))
	require.ErrorContains(t, ValidateClientAuthClaims(claims, "expected", time.Hour), "token lifetime exceeds maximum")
}
