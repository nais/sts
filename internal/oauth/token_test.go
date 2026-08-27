package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestAccessTokenClaims(t *testing.T) {
	at, _ := CreateAccessToken(
		"issuer",
		"subject",
		"client_id",
		[]string{"audience"},
		nil,
		3600*time.Second,
		map[string]any{"iss": "foo", "foo": "bar"},
	)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, nil)

	tok, _ := at.Sign(signer)
	println(tok)
}
