package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAccessTokenClaimsUnmarshal(t *testing.T) {
	data := []byte(`{"iss":"issuer","sub":"subject","aud":["audience"],"custom":{"number":9007199254740993,"items":[1,true]}}`)
	claims := new(jwt.AccessTokenClaims)

	require.NoError(t, json.Unmarshal(data, claims))
	assert.Equal(t, "issuer", claims.Issuer)
	assert.Equal(t, "subject", claims.Subject)
	assert.Equal(t, oidc.Audience{"audience"}, claims.Audience)
	assert.JSONEq(t, `{"number":9007199254740993,"items":[1,true]}`, string(claims.Claims["custom"]))
}

func TestCreateAccessTokenRestartsMalformedCallChain(t *testing.T) {
	const stsIssuer api.STSIssuer = "https://sts.example"

	claims, err := CreateAccessToken(stsIssuer, nil, time.Hour, &AuthorizationResult{
		Target:    TargetAudience("audience"),
		GrantType: oidc.GrantTypeTokenExchange,
		Client:    &Client{ID: "client"},
		SubjectTokenClaims: &jwt.AccessTokenClaims{
			Issuer:  string(stsIssuer),
			Subject: "subject",
			Claims:  map[string]json.RawMessage{"urn:nais:call_chain": json.RawMessage(`{"client_id":"previous-actor"}`)},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []ClientID{"client"}, claims.CallChain)
}

func TestAccessTokenClaimsKubernetes(t *testing.T) {
	for name, test := range map[string]struct {
		claims map[string]json.RawMessage
		want   string
	}{
		"missing":      {claims: map[string]json.RawMessage{}, want: "kubernetes.io claim is missing"},
		"malformed":    {claims: map[string]json.RawMessage{"kubernetes.io": json.RawMessage(`"text"`)}, want: "kubernetes.io claim is malformed"},
		"empty fields": {claims: map[string]json.RawMessage{"kubernetes.io": json.RawMessage(`{"namespace":"ns"}`)}, want: "kubernetes.io claim has no namespace or service account name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&jwt.AccessTokenClaims{Claims: test.claims}).Kubernetes()
			assert.ErrorContains(t, err, test.want)
			if name == "malformed" {
				assert.ErrorContains(t, err, "cannot unmarshal string")
			}
		})
	}
}
