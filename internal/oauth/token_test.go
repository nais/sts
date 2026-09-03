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
		"act":    json.RawMessage(`{"sub":"stale-actor"}`),
		"custom": json.RawMessage(`{"number":9007199254740993}`),
	}
	original := cloneClaims(source)
	accessToken, err := CreateAccessToken(
		"sts-issuer", "subject", "client", oidc.Audience{"audience"}, nil, time.Hour, nil, source,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONClaim(t, accessToken.Claims, "iss", "sts-issuer")
	assertJSONClaim(t, accessToken.Claims, "sub", "subject")
	assertJSONClaim(t, accessToken.Claims, "client_id", "client")
	if got, want := string(accessToken.Claims["act"]), `{"sub":"stale-actor"}`; got != want {
		t.Fatalf("act claim = %s, want %s", got, want)
	}
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
	assertJSONClaim(t, got, "sub", "subject")
	assertJSONClaim(t, got, "client_id", "client")
	if got, want := string(got["act"]), `{"sub":"stale-actor"}`; got != want {
		t.Fatalf("act claim = %s, want %s", got, want)
	}
	if got, want := string(got["custom"]), `{"number":9007199254740993}`; got != want {
		t.Fatalf("custom claim = %s, want %s", got, want)
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
