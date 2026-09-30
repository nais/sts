package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
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
	IDP              string                     `json:"urn:nais:idp,omitempty"`
	IDPName          string                     `json:"urn:nais:idp_name,omitempty"`
	Claims           map[string]json.RawMessage `json:"-"`
}

type ActorClaims struct {
	Actor    json.RawMessage `json:"act,omitempty"`
	Issuer   string          `json:"iss,omitempty"`
	ClientID string          `json:"client_id"`
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

func CreateAccessToken(issuer Issuer, subjectTokenIssuers map[Issuer]string, expiresIn time.Duration, result *AuthorizationResult) (*STSTokenClaims, error) {
	subject := result.Client.ID
	var subjectTokenClaims map[string]json.RawMessage

	if result.SubjectTokenClaims != nil {
		subject = result.SubjectTokenClaims.Subject
		subjectTokenClaims = result.SubjectTokenClaims.Claims
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
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,

		// urn:nais:*
		ApplicationRoles: result.Roles,
		GrantType:        result.GrantType,
	}

	if result.GrantType == oidc.GrantTypeTokenExchange {
		stsTokenClaims.Actor = &ActorClaims{
			// TODO: use subject token issuer
			Issuer:   string(issuer),
			ClientID: result.Client.ID,
		}
		if raw, ok := subjectTokenClaims["act"]; ok {
			if err := validateActorClaims(raw); err != nil {
				return nil, fmt.Errorf("decode subject token actor claim: %w", err)
			}
			stsTokenClaims.Actor.Actor = raw
		}
		// TODO: properly decode the subject token issuer and name from the subject token claims, instead of hardcoding them here.
		subIssuer, err := strconv.Unquote(string(subjectTokenClaims["iss"]))
		if err != nil {
			return nil, fmt.Errorf("decode subject token issuer: %w", err)
		}
		idpName, ok := subjectTokenIssuers[Issuer(subIssuer)]
		if ok {
			stsTokenClaims.IDP = subIssuer
			stsTokenClaims.IDPName = idpName
		}
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}
	stsTokenClaims.Claims = claims

	return &stsTokenClaims, nil
}

// Validate nonempty actor objects and unique keys before nesting the raw actor chain in an STS token.
func validateActorClaims(raw json.RawMessage) error {
	return validateActor(json.NewDecoder(bytes.NewReader(raw)))
}

func validateActor(decoder *json.Decoder) error {
	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start != json.Delim('{') {
		return fmt.Errorf("actor must be an object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name := key.(string)
		if seen[name] {
			return fmt.Errorf("duplicate actor claim %q", name)
		}
		seen[name] = true
		if name == "act" {
			if err := validateActor(decoder); err != nil {
				return err
			}
		} else {
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return err
			}
		}
	}
	if len(seen) == 0 {
		return fmt.Errorf("actor must be a nonempty object")
	}
	_, err = decoder.Token()
	return err
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
