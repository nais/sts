package oauth

import (
	"encoding/json"
	"fmt"
	"maps"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type STSTokenClaims struct {
	Issuer           string                     `json:"iss"`
	Subject          string                     `json:"sub"`
	Audience         oidc.Audience              `json:"aud"`
	ClientID         string                     `json:"client_id"`
	JWTID            string                     `json:"jti"`
	Actor            *ActorClaims               `json:"act,omitempty"`
	Expiration       oidc.Time                  `json:"exp"`
	IssuedAt         oidc.Time                  `json:"iat"`
	NotBefore        oidc.Time                  `json:"nbf"`
	ApplicationRoles Roles                      `json:"urn:nais:roles,omitempty"`
	GrantType        oidc.GrantType             `json:"urn:nais:grant_type,omitempty"` // TODO: add human-readable alias (m2m, tokenx/obo)
	Claims           map[string]json.RawMessage `json:"-"`
}

type ActorClaims struct {
	Actor    *ActorClaims `json:"act,omitempty"`
	Issuer   string       `json:"iss,omitempty"`
	ClientID string       `json:"client_id"`
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

func CreateAccessToken(issuer Issuer, expiresIn time.Duration, result *AuthorizationResult) (*STSTokenClaims, error) {
	subject := result.Client.ID
	var subjectTokenClaims map[string]json.RawMessage

	if result.SubjectTokenClaims != nil {
		subject = result.SubjectTokenClaims.Subject
		subjectTokenClaims = result.SubjectTokenClaims.Claims
	}

	var actor *ActorClaims
	if result.GrantType == oidc.GrantTypeTokenExchange {
		actor = &ActorClaims{
			Issuer:   string(issuer),
			ClientID: result.Client.ID,
		}
		if raw, ok := subjectTokenClaims["act"]; ok {
			previous, err := parseActorClaims(raw)
			if err != nil {
				return nil, fmt.Errorf("decode subject token actor claim: %w", err)
			}
			actor.Actor = previous
		}
	}

	jti := uuid.New().String()
	now := time.Now()
	exp := oidc.FromTime(now.Add(expiresIn))
	iat := oidc.FromTime(now)
	nbf := iat

	// TODO: review the claims we want or need to set (act, urn:nais, etc.)
	stsTokenClaims := STSTokenClaims{
		Issuer:     string(issuer),
		Subject:    subject,
		Audience:   result.Target.AsAudience(),
		ClientID:   result.Client.ID,
		JWTID:      jti,
		Actor:      actor,
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,

		// urn:nais:*
		ApplicationRoles: result.Roles,
		GrantType:        result.GrantType,
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}
	stsTokenClaims.Claims = claims

	return &stsTokenClaims, nil
}

func parseActorClaims(raw json.RawMessage) (*ActorClaims, error) {
	actor := new(ActorClaims)
	if err := json.Unmarshal(raw, actor); err != nil {
		return nil, err
	}
	if actor.ClientID == "" {
		return nil, fmt.Errorf("client ID is missing")
	}
	return actor, nil
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
