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

	claims, err := (&AuthorizationServer{
		Issuer:      stsIssuer,
		TokenExpiry: time.Hour,
	}).CreateAccessToken(&AuthorizationResult{
		Target: "audience",
		Caller: CallerIdentity{Client: &Client{ID: "client"}},
		SubjectTokenClaims: &jwt.AccessTokenClaims{
			Issuer:  string(stsIssuer),
			Subject: "subject",
			Claims:  map[string]json.RawMessage{"urn:nais:call_chain": json.RawMessage(`{"client_id":"previous-actor"}`)},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []ClientID{"client"}, claims.CallChain)
}

func TestCreateAccessTokenDropsUntrustedImpersonator(t *testing.T) {
	const stsIssuer api.STSIssuer = "https://sts.example"
	for _, tt := range []struct {
		name          string
		subjectIssuer string
		subjectClaim  string
	}{
		{name: "external claim ignored", subjectIssuer: "https://external.example", subjectClaim: `{"issuer":"https://people.example","subject":"alice"}`},
		{name: "malformed STS history dropped", subjectIssuer: string(stsIssuer), subjectClaim: `{"issuer":"https://people.example"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			subjectClaims := map[string]json.RawMessage{"urn:nais:impersonator": json.RawMessage(tt.subjectClaim)}
			server := &AuthorizationServer{
				Issuer:          stsIssuer,
				TokenExpiry:     time.Hour,
				ExternalIssuers: IssuerAliases{"external": "https://external.example"},
			}
			claims, err := server.CreateAccessToken(&AuthorizationResult{
				Target:             "audience",
				Caller:             CallerIdentity{Client: &Client{ID: "client"}},
				SubjectTokenClaims: &jwt.AccessTokenClaims{Issuer: tt.subjectIssuer, Subject: "subject", Claims: subjectClaims},
			})
			require.NoError(t, err)
			assert.NotContains(t, claims.Claims, "urn:nais:impersonator")
		})
	}
}
