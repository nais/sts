package oauth

import (
	"encoding/json"
	"maps"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type STSTokenClaims struct {
	Issuer     string            `json:"iss,omitempty"`
	Subject    string            `json:"sub,omitempty"`
	Audience   oidc.Audience     `json:"aud,omitempty"`
	ClientID   string            `json:"client_id,omitempty"`
	JWTID      string            `json:"jti,omitempty"`
	Actor      *oidc.ActorClaims `json:"act,omitempty"`
	Expiration oidc.Time         `json:"exp,omitempty"`
	IssuedAt   oidc.Time         `json:"iat,omitempty"`
	NotBefore  oidc.Time         `json:"nbf,omitempty"`
}

type AccessTokenClaims struct {
	oidc.TokenClaims
	Claims map[string]json.RawMessage `json:"-"`
}

func (a *AccessTokenClaims) ExpiresIn() time.Duration {
	return time.Until(a.Expiration.AsTime())
}

func (a *AccessTokenClaims) Sign(signer jose.Signer) (string, error) {
	return crypto.Sign(a.Claims, signer)
}

var _ json.Unmarshaler = (*AccessTokenClaims)(nil)

func (a *AccessTokenClaims) UnmarshalJSON(data []byte) error {
	type tokenClaims oidc.TokenClaims
	if err := json.Unmarshal(data, (*tokenClaims)(&a.TokenClaims)); err != nil {
		return err
	}
	return json.Unmarshal(data, &a.Claims)
}

func CreateAccessToken(
	issuer, subject, clientID string,
	audience oidc.Audience,
	actor *oidc.ActorClaims,
	expiresIn time.Duration,
	subjectTokenClaims map[string]json.RawMessage,
) (*AccessTokenClaims, error) {
	jti := uuid.New().String()
	now := time.Now()
	exp := oidc.FromTime(now.Add(expiresIn))
	iat := oidc.FromTime(now)
	nbf := iat

	stsTokenClaims := oidc.TokenClaims{
		Issuer:     issuer,
		Subject:    subject,
		Audience:   audience,
		ClientID:   clientID,
		JWTID:      jti,
		Actor:      actor,
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}

	return &AccessTokenClaims{
		TokenClaims: stsTokenClaims,
		Claims:      claims,
	}, nil
}

func mergeClaims(base map[string]json.RawMessage, authoritative any) (map[string]json.RawMessage, error) {
	claims := make(map[string]json.RawMessage, len(base))
	maps.Copy(claims, base)

	data, err := json.Marshal(authoritative)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}
	return claims, nil
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
	issuer, subject, clientID string,
	audience oidc.Audience,
	actor *oidc.ActorClaims,
	expiresIn time.Duration,
	subjectTokenClaims map[string]json.RawMessage,
) (*AccessTokenClaims, error) {
	return CreateAccessToken(
		issuer, subject, clientID, audience, actor, expiresIn, subjectTokenClaims,
	)
}
