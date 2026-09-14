package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAccessTokenClaimsUnmarshal(t *testing.T) {
	data := []byte(`{"iss":"issuer","sub":"subject","aud":["audience"],"custom":{"number":9007199254740993,"items":[1,true]}}`)
	claims := new(AccessTokenClaims)

	if err := json.Unmarshal(data, claims); err != nil {
		t.Fatal(err)
	}

	if claims.Issuer != "issuer" || claims.Subject != "subject" || !reflect.DeepEqual(claims.Audience, oidc.Audience{"audience"}) {
		t.Fatalf("unexpected typed claims: %#v", claims.TokenClaims)
	}
	if got, want := string(claims.Claims["custom"]), `{"number":9007199254740993,"items":[1,true]}`; got != want {
		t.Fatalf("custom claim = %s, want %s", got, want)
	}
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
	accessToken, err := CreateAccessToken("sts-issuer", time.Hour, result)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONClaim(t, accessToken.Claims, "iss", "sts-issuer")
	assertJSONClaim(t, accessToken.Claims, "sub", "source-subject")
	assertJSONClaim(t, accessToken.Claims, "client_id", "client")
	assertActorClaim(t, accessToken.Claims["act"], "sts-issuer", "client", "previous-issuer", "previous-actor")
	if !reflect.DeepEqual(source, original) {
		t.Fatal("creating access token mutated source claims")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := accessToken.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[string]json.RawMessage)
	if _, err := oidc.ParseToken(signed, &got); err != nil {
		t.Fatal(err)
	}
	assertJSONClaim(t, got, "iss", "sts-issuer")
	assertJSONClaim(t, got, "sub", "source-subject")
	assertJSONClaim(t, got, "client_id", "client")
	assertActorClaim(t, got["act"], "sts-issuer", "client", "previous-issuer", "previous-actor")
	if got, want := string(got["custom"]), `{"number":9007199254740993}`; got != want {
		t.Fatalf("custom claim = %s, want %s", got, want)
	}
}

func TestCreateAccessTokenOmitsActorForClientCredentials(t *testing.T) {
	token, err := CreateAccessToken("sts-issuer", time.Hour, &AuthorizationResult{
		Target:    TargetScope("target"),
		GrantType: oidc.GrantTypeClientCredentials,
		Client:    &Client{ID: "client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := token.Claims["act"]; ok {
		t.Fatal("client credentials token contains act claim")
	}
}

func TestCreateAccessTokenRejectsMalformedActor(t *testing.T) {
	_, err := CreateAccessToken("sts-issuer", time.Hour, &AuthorizationResult{
		Target:    TargetAudience("target"),
		GrantType: oidc.GrantTypeTokenExchange,
		SubjectTokenClaims: &AccessTokenClaims{
			Subject: "subject",
			Claims:  map[string]json.RawMessage{"act": json.RawMessage(`"invalid"`)},
		},
		Client: &Client{ID: "client"},
	})
	if err == nil {
		t.Fatal("expected malformed actor claim to fail")
	}
}

func TestCreateAccessTokenRejectsEmptyActor(t *testing.T) {
	_, err := CreateAccessToken("sts-issuer", time.Hour, &AuthorizationResult{
		Target:    TargetAudience("target"),
		GrantType: oidc.GrantTypeTokenExchange,
		SubjectTokenClaims: &AccessTokenClaims{
			Subject: "subject",
			Claims:  map[string]json.RawMessage{"act": json.RawMessage(`{}`)},
		},
		Client: &Client{ID: "client"},
	})
	if err == nil {
		t.Fatal("expected empty actor claim to fail")
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
	if err := json.Unmarshal(claims[name], &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s claim = %q, want %q", name, got, want)
	}
}

func assertActorClaim(t *testing.T, raw json.RawMessage, issuer, subject, previousIssuer, previousSubject string) {
	t.Helper()
	actor := new(ActorClaims)
	if err := json.Unmarshal(raw, actor); err != nil {
		t.Fatal(err)
	}
	if actor.Issuer != issuer || actor.ClientID != subject {
		t.Fatalf("actor = %#v, want issuer %q and subject %q", actor, issuer, subject)
	}
	if actor.Actor == nil || actor.Actor.Issuer != previousIssuer || actor.Actor.ClientID != previousSubject {
		t.Fatalf("previous actor = %#v, want issuer %q and subject %q", actor.Actor, previousIssuer, previousSubject)
	}
}
