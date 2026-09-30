package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAccessTokenClaimsUnmarshal(t *testing.T) {
	data := []byte(`{"iss":"issuer","sub":"subject","aud":["audience"],"custom":{"number":9007199254740993,"items":[1,true]}}`)
	claims := new(AccessTokenClaims)

	require.NoError(t, json.Unmarshal(data, claims))
	assert.Equal(t, "issuer", claims.Issuer)
	assert.Equal(t, "subject", claims.Subject)
	assert.Equal(t, oidc.Audience{"audience"}, claims.Audience)
	assert.JSONEq(t, `{"number":9007199254740993,"items":[1,true]}`, string(claims.Claims["custom"]))
}

func TestAccessTokenClaimsSign(t *testing.T) {
	source := map[string]json.RawMessage{
		"iss":    json.RawMessage(`"source-issuer"`),
		"sub":    json.RawMessage(`"source-subject"`),
		"act":    json.RawMessage(`{"iss":"previous-issuer","client_id":"previous-actor"}`),
		"custom": json.RawMessage(`{"number":9007199254740993}`),
	}
	original := cloneClaims(source)
	result := &AuthorizationResult{
		Target:    TargetAudience("audience"),
		GrantType: oidc.GrantTypeTokenExchange,
		SubjectTokenClaims: &AccessTokenClaims{
			Subject: "source-subject",
			Claims:  source,
		},
		Client: &Client{
			ID: "client",
		},
		Roles: nil,
	}
	accessToken, err := CreateAccessToken("sts-issuer", nil, time.Hour, result)
	require.NoError(t, err)
	assert.Equal(t, original, source)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	require.NoError(t, err)
	signed, err := accessToken.Sign(signer)
	require.NoError(t, err)

	got := make(map[string]json.RawMessage)
	_, err = oidc.ParseToken(signed, &got)
	require.NoError(t, err)
	assertJSONClaim(t, got, "iss", "sts-issuer")
	assertJSONClaim(t, got, "sub", "source-subject")
	assertJSONClaim(t, got, "client_id", "client")
	assertActorClaim(t, got["act"], "sts-issuer", "client", "previous-issuer", "previous-actor")
	assert.JSONEq(t, `{"number":9007199254740993}`, string(got["custom"]))
}

func TestValidateActorClaimsRejectsInvalidActor(t *testing.T) {
	for name, actor := range map[string]json.RawMessage{
		"malformed":        json.RawMessage(`"invalid"`),
		"null":             json.RawMessage(`null`),
		"empty":            json.RawMessage(`{}`),
		"nested":           json.RawMessage(`{"sub":"actor","act":[]}`),
		"duplicate":        json.RawMessage(`{"sub":"first","sub":"second"}`),
		"nested duplicate": json.RawMessage(`{"sub":"actor","act":{"sub":"first","sub":"second"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateActorClaims(actor)
			assert.Error(t, err)
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

func assertActorClaim(t *testing.T, raw json.RawMessage, issuer, subject, previousIssuer, previousSubject string) {
	t.Helper()

	actor := new(ActorClaims)
	require.NoError(t, json.Unmarshal(raw, actor))
	assert.Equal(t, issuer, actor.Issuer)
	assert.Equal(t, subject, actor.ClientID)
	require.NotEmpty(t, actor.Actor)

	previous := new(ActorClaims)
	require.NoError(t, json.Unmarshal(actor.Actor, previous))
	assert.Equal(t, previousIssuer, previous.Issuer)
	assert.Equal(t, previousSubject, previous.ClientID)
}
