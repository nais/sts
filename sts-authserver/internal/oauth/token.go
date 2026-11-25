package oauth

import (
	"encoding/json"
	"fmt"
	"maps"
	"time"
	"uuid"

	"github.com/nais/sts/internal/jwk"
	"github.com/nais/sts/internal/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const InternalSigningAlgorithm = jwk.Algorithm

type STSTokenClaims struct {
	Issuer           string        `json:"iss"`
	Subject          string        `json:"sub,omitempty"`
	Audience         oidc.Audience `json:"aud"`
	ClientID         string        `json:"client_id"`
	JWTID            string        `json:"jti"`
	Expiration       oidc.Time     `json:"exp"`
	IssuedAt         oidc.Time     `json:"iat"`
	NotBefore        oidc.Time     `json:"nbf"`
	CallChain        []ClientID    `json:"urn:nais:call_chain,omitempty"`
	ApplicationRoles Roles         `json:"urn:nais:roles,omitempty"`
	// Empty values are omitted so mergeClaims keeps the subject-token claims.
	IDP      string `json:"urn:nais:idp,omitempty"`
	IDPAlias string `json:"urn:nais:idp_alias,omitempty"`
	// Impersonator records the impersonation that started an STS exchange chain.
	Impersonator *Impersonator              `json:"urn:nais:impersonator,omitempty"`
	Claims       map[string]json.RawMessage `json:"-"`
}

func (s *STSTokenClaims) ExpiresIn() time.Duration {
	return time.Until(s.Expiration.AsTime())
}

func (s *STSTokenClaims) Sign(signer *jwk.Signer) (string, error) {
	return signer.SignJWT(s.Claims)
}

func (a *AuthorizationServer) CreateAccessToken(result *AuthorizationResult) (*STSTokenClaims, error) {
	subjectTokenClaims := result.SubjectTokenClaims.Claims

	jti := uuid.New().String()
	now := time.Now()
	exp := oidc.FromTime(now.Add(a.TokenExpiry))
	iat := oidc.FromTime(now)
	nbf := iat

	// TODO: review the claims we want or need to set (urn:nais, etc.)
	stsTokenClaims := STSTokenClaims{
		Issuer:     string(a.Issuer),
		Subject:    result.SubjectTokenClaims.Subject,
		Audience:   result.Target.Audience(),
		ClientID:   string(result.Caller.ID),
		JWTID:      jti,
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,

		// urn:nais:*
		ApplicationRoles: result.Roles,
	}

	subjectIssuer := result.SubjectTokenClaims.Issuer
	stsTokenClaims.CallChain = []ClientID{result.Caller.ID}
	stsTokenClaims.Impersonator = result.Caller.Impersonator

	// Only extend chains issued by STS; external or malformed chains start over.
	if subjectIssuer == string(a.Issuer) {
		var previous []ClientID
		raw, ok := subjectTokenClaims["urn:nais:call_chain"]
		if ok && json.Unmarshal(raw, &previous) == nil {
			stsTokenClaims.CallChain = append(previous, result.Caller.ID)
		}

		// Impersonation is only allowed on the first exchange, so later exchanges keep it as history.
		var impersonator Impersonator
		raw, ok = subjectTokenClaims["urn:nais:impersonator"]
		if ok && json.Unmarshal(raw, &impersonator) == nil && impersonator.Issuer != "" && impersonator.Subject != "" {
			stsTokenClaims.Impersonator = &impersonator
		}
	} else {
		issuerAlias, ok := a.GetIssuerAlias(jwt.Issuer(subjectIssuer))
		if !ok {
			return nil, fmt.Errorf("issuer alias for %q not found", subjectIssuer)
		}
		stsTokenClaims.IDP = subjectIssuer
		stsTokenClaims.IDPAlias = issuerAlias
	}

	claims, err := mergeClaims(subjectTokenClaims, stsTokenClaims)
	if err != nil {
		return nil, err
	}

	// Empty policy roles must not inherit roles from the subject token.
	if len(result.Roles) == 0 {
		delete(claims, "urn:nais:roles")
	}
	// Only STS may set the impersonator; drop values copied from external or malformed tokens.
	if stsTokenClaims.Impersonator == nil {
		delete(claims, "urn:nais:impersonator")
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
