package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAccessTokenRestartsMalformedCallChain(t *testing.T) {
	const stsIssuer api.STSIssuer = "https://sts.example"

	claims, err := (&AuthorizationServer{AuthorizationServerConfig: AuthorizationServerConfig{
		Issuer:      stsIssuer,
		TokenExpiry: time.Hour,
	}}).CreateAccessToken(&AuthorizationResult{
		Target: "audience",
		Client: &Client{ID: "client"},
		SubjectTokenClaims: &jwt.AccessTokenClaims{
			Issuer:  string(stsIssuer),
			Subject: "subject",
			Claims:  map[string]json.RawMessage{"urn:nais:call_chain": json.RawMessage(`{"client_id":"previous-actor"}`)},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []ClientID{"client"}, claims.CallChain)
}
