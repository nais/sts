package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwk"
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

func TestAccessTokenClaimsSign(t *testing.T) {
	source := map[string]json.RawMessage{
		"iss":            json.RawMessage(`"sts-issuer"`),
		"sub":            json.RawMessage(`"source-subject"`),
		"act":            json.RawMessage(`{"iss":"previous-issuer","client_id":"previous-actor"}`),
		"custom":         json.RawMessage(`{"number":9007199254740993}`),
		"urn:nais:roles": json.RawMessage(`["source-role"]`),
	}
	original := cloneClaims(source)
	result := &AuthorizationResult{
		Target:    TargetAudience("audience"),
		GrantType: oidc.GrantTypeTokenExchange,
		SubjectTokenClaims: &jwt.AccessTokenClaims{
			Issuer: "sts-issuer", Subject: "source-subject",
			Claims: source,
		},
		Client: &Client{
			ID: "client",
		},
		Roles: nil,
	}
	accessToken, err := CreateAccessToken("sts-issuer", nil, time.Hour, result)
	require.NoError(t, err)
	assert.Equal(t, original, source)

	signer, err := jwk.GenerateSigner()
	require.NoError(t, err)

	signed, err := accessToken.Sign(signer)
	require.NoError(t, err)

	got := make(map[string]json.RawMessage)
	_, err = oidc.ParseToken(signed, &got)
	require.NoError(t, err)
	assertJSONClaim(t, got, "iss", "sts-issuer")
	assertJSONClaim(t, got, "sub", "source-subject")
	assertJSONClaim(t, got, "client_id", "client")
	assertActorClaim(t, got["act"], "client", "previous-actor")
	assert.JSONEq(t, `{"number":9007199254740993}`, string(got["custom"]))
	assert.NotContains(t, got, "urn:nais:roles")
}

func TestCreateAccessTokenIssuerRoles(t *testing.T) {
	const stsIssuer api.STSIssuer = "https://sts.example"
	const externalIssuer TokenIssuer = "https://idp.example"

	for _, test := range []struct {
		name          string
		subjectIssuer TokenIssuer
		wantActor     bool
		wantIDP       string
		wantIDPName   string
	}{
		{name: "STS", subjectIssuer: TokenIssuer(stsIssuer), wantActor: true},
		{name: "external", subjectIssuer: externalIssuer, wantIDP: string(externalIssuer), wantIDPName: "idp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims, err := CreateAccessToken(stsIssuer, map[TokenIssuer]string{externalIssuer: "idp"}, time.Hour, &AuthorizationResult{
				Target:    TargetAudience("audience"),
				GrantType: oidc.GrantTypeTokenExchange,
				Client:    &Client{ID: "client"},
				SubjectTokenClaims: &jwt.AccessTokenClaims{
					Issuer:  string(test.subjectIssuer),
					Subject: "subject",
					Claims: map[string]json.RawMessage{
						"act": json.RawMessage(`{"client_id":"previous-actor"}`),
					},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, string(stsIssuer), claims.Issuer)
			assert.Equal(t, test.wantIDP, claims.IDP)
			assert.Equal(t, test.wantIDPName, claims.IDPName)
			require.NotNil(t, claims.Actor)
			assert.Equal(t, "client", claims.Actor.ClientID)
			if test.wantActor {
				assert.JSONEq(t, `{"client_id":"previous-actor"}`, string(claims.Actor.Actor))
			} else {
				assert.Empty(t, claims.Actor.Actor)
			}
		})
	}
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

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	clone := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		clone[name] = append(json.RawMessage(nil), value...)
	}
	return clone
}

func assertJSONClaim(t *testing.T, claims map[string]json.RawMessage, name, want string) {
	t.Helper()
	var got string
	require.NoError(t, json.Unmarshal(claims[name], &got))
	assert.Equal(t, want, got, name)
}

func assertActorClaim(t *testing.T, raw json.RawMessage, subject, previousSubject string) {
	t.Helper()

	actor := new(ActorClaims)
	require.NoError(t, json.Unmarshal(raw, actor))
	assert.Equal(t, subject, actor.ClientID)
	require.NotEmpty(t, actor.Actor)

	previous := new(ActorClaims)
	require.NoError(t, json.Unmarshal(actor.Actor, previous))
	assert.Equal(t, previousSubject, previous.ClientID)
}
