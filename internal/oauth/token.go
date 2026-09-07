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
	oidc.TokenClaims
	ApplicationRoles Roles                      `json:"application_roles,omitempty"`
	Claims           map[string]json.RawMessage `json:"-"`
}

func (s *STSTokenClaims) ExpiresIn() time.Duration {
	return time.Until(s.Expiration.AsTime())
}

func (s *STSTokenClaims) Sign(signer jose.Signer) (string, error) {
	return crypto.Sign(s.Claims, signer)
}

var _ json.Unmarshaler = (*AccessTokenClaims)(nil)

type AccessTokenClaims struct {
	oidc.TokenClaims
	Claims map[string]json.RawMessage `json:"-"`
}

func (a *AccessTokenClaims) UnmarshalJSON(data []byte) error {
	// Use a distinct type without UnmarshalJSON to avoid recursive unmarshalling.
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
	roles Roles,
	subjectTokenClaims map[string]json.RawMessage,
) (*STSTokenClaims, error) {
	jti := uuid.New().String()
	now := time.Now()
	exp := oidc.FromTime(now.Add(expiresIn))
	iat := oidc.FromTime(now)
	nbf := iat
	// TODO: review the claims we want or need to set (act, urn:nais, etc.)
	// TODO: add urn:nais:grant_type (or similar) to denote the type of grant used to acquire the token
	stsTokenClaims := STSTokenClaims{
		Issuer:           issuer,
		Subject:          subject,
		Audience:         audience,
		ClientID:         clientID,
		JWTID:            jti,
		Actor:            actor,
		Expiration:       exp,
		IssuedAt:         iat,
		NotBefore:        nbf,
		ApplicationRoles: roles,
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}
	stsTokenClaims.Claims = claims

	return &stsTokenClaims, nil
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
