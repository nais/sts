package oauth

import (
	"encoding/json"
	"maps"
	"time"
	"uuid"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwk"
	"github.com/nais/sts/internal/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const InternalSigningAlgorithm = jwk.Algorithm

type STSTokenClaims struct {
	Issuer           string                     `json:"iss"`
	Subject          string                     `json:"sub"`
	Audience         oidc.Audience              `json:"aud"`
	ClientID         string                     `json:"client_id"`
	JWTID            string                     `json:"jti"`
	Expiration       oidc.Time                  `json:"exp"`
	IssuedAt         oidc.Time                  `json:"iat"`
	NotBefore        oidc.Time                  `json:"nbf"`
	CallChain        []ClientID                 `json:"urn:nais:call_chain,omitempty"`
	ApplicationRoles Roles                      `json:"urn:nais:roles,omitempty"`
	GrantType        oidc.GrantType             `json:"urn:nais:grant_type,omitempty"` // TODO: add human-readable alias (m2m, tokenx/obo)
	IDP              string                     `json:"urn:nais:idp,omitempty"`
	IDPName          string                     `json:"urn:nais:idp_name,omitempty"`
	Claims           map[string]json.RawMessage `json:"-"`
}

func (s *STSTokenClaims) ExpiresIn() time.Duration {
	return time.Until(s.Expiration.AsTime())
}

func (s *STSTokenClaims) Sign(signer *jwk.Signer) (string, error) {
	return signer.SignJWT(s.Claims)
}

func CreateAccessToken(issuer api.STSIssuer, subjectTokenIssuers map[jwt.Issuer]string, expiresIn time.Duration, result *AuthorizationResult) (*STSTokenClaims, error) {
	subject := string(result.Client.ID)
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

	// TODO: review the claims we want or need to set (urn:nais, etc.)
	stsTokenClaims := STSTokenClaims{
		Issuer:     string(issuer),
		Subject:    subject,
		Audience:   result.Target.AsAudience(),
		ClientID:   string(result.Client.ID),
		JWTID:      jti,
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,

		// urn:nais:*
		ApplicationRoles: result.Roles,
		GrantType:        result.GrantType,
	}

	if result.GrantType == oidc.GrantTypeTokenExchange {
		subjectIssuer := jwt.Issuer(result.SubjectTokenClaims.Issuer)
		stsTokenClaims.CallChain = []ClientID{result.Client.ID}

		// Only extend chains issued by STS; external or malformed chains start over.
		if subjectIssuer == jwt.Issuer(issuer) {
			var previous []ClientID
			raw, ok := subjectTokenClaims["urn:nais:call_chain"]
			if ok && json.Unmarshal(raw, &previous) == nil {
				stsTokenClaims.CallChain = append(previous, result.Client.ID)
			}
		}

		idpName, ok := subjectTokenIssuers[subjectIssuer]
		if ok {
			stsTokenClaims.IDP = string(subjectIssuer)
			stsTokenClaims.IDPName = idpName
		}
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}

	// Empty policy roles must not inherit roles from the subject token.
	if len(result.Roles) == 0 {
		delete(claims, "urn:nais:roles")
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
