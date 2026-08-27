package oauth

import (
	"encoding/json"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AccessTokenClaims struct {
	Issuer     string            `json:"iss,omitempty"`
	Subject    string            `json:"sub,omitempty"`
	Audience   oidc.Audience     `json:"aud,omitempty"`
	ClientID   string            `json:"client_id,omitempty"`
	JWTID      string            `json:"jti,omitempty"`
	Actor      *oidc.ActorClaims `json:"act,omitempty"`
	Expiration oidc.Time         `json:"exp,omitempty"`
	IssuedAt   oidc.Time         `json:"iat,omitempty"`
	NotBefore  oidc.Time         `json:"nbf,omitempty"`

	SubjectTokenClaims map[string]any `json:"-"`
}

func (a *AccessTokenClaims) ExpiresIn() time.Duration {
	return time.Until(a.Expiration.AsTime())
}

func (a *AccessTokenClaims) Sign(signer jose.Signer) (string, error) {
	// TODO: tests for merging/overriding with nested values, objects, arrays
	claims := a.SubjectTokenClaims
	if claims == nil {
		claims = make(map[string]any)
	}

	atClaims, err := json.Marshal(a)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(atClaims, &claims)
	if err != nil {
		return "", err
	}

	return crypto.Sign(claims, signer)
}

func CreateAccessToken(
	issuer, subject, clientID string,
	audience oidc.Audience,
	actor *oidc.ActorClaims,
	expiresIn time.Duration,
	privateClaims map[string]any,
) (*AccessTokenClaims, error) {
	jti := uuid.New().String()
	now := time.Now()
	exp := oidc.FromTime(now.Add(expiresIn))
	iat := oidc.FromTime(now)
	nbf := iat

	return &AccessTokenClaims{
		Issuer:             issuer,
		Subject:            subject,
		Audience:           audience,
		ClientID:           clientID,
		JWTID:              jti,
		Actor:              actor,
		Expiration:         exp,
		IssuedAt:           iat,
		NotBefore:          nbf,
		SubjectTokenClaims: privateClaims,
	}, nil
}

func CreateClientCredentialsAccessToken(
	issuer, clientID string,
	audience oidc.Audience,
	actor *oidc.ActorClaims,
	expiresIn time.Duration,
) (*AccessTokenClaims, error) {
	return CreateAccessToken(
		issuer, clientID, clientID, audience, actor, expiresIn, nil,
	)
}

func CreateTokenExchangeAccessToken(
	issuer, clientID string,
	audience oidc.Audience,
	actor *oidc.ActorClaims,
	expiresIn time.Duration,
	privateClaims map[string]any,
) (*AccessTokenClaims, error) {
	return CreateAccessToken(
		issuer, "", clientID, audience, actor, expiresIn, privateClaims,
	)
}
