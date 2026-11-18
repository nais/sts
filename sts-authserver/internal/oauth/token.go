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
	Subject          string        `json:"sub"`
	Audience         oidc.Audience `json:"aud"`
	ClientID         string        `json:"client_id"`
	JWTID            string        `json:"jti"`
	Expiration       oidc.Time     `json:"exp"`
	IssuedAt         oidc.Time     `json:"iat"`
	NotBefore        oidc.Time     `json:"nbf"`
	CallChain        []ClientID    `json:"urn:nais:call_chain,omitempty"`
	ApplicationRoles Roles         `json:"urn:nais:roles,omitempty"`
	// Empty values are omitted so mergeClaims keeps the subject-token claims.
	IDP      string                     `json:"urn:nais:idp,omitempty"`
	IDPAlias string                     `json:"urn:nais:idp_alias,omitempty"`
	Claims   map[string]json.RawMessage `json:"-"`
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
		Audience:   result.Target.AsAudience(),
		ClientID:   string(result.Client.ID),
		JWTID:      jti,
		Expiration: exp,
		IssuedAt:   iat,
		NotBefore:  nbf,

		// urn:nais:*
		ApplicationRoles: result.Roles,
	}

	subjectIssuer := jwt.Issuer(result.SubjectTokenClaims.Issuer)
	stsTokenClaims.CallChain = []ClientID{result.Client.ID}

	// Only extend chains issued by STS; external or malformed chains start over.
	if subjectIssuer == jwt.Issuer(a.Issuer) {
		var previous []ClientID
		raw, ok := subjectTokenClaims["urn:nais:call_chain"]
		if ok && json.Unmarshal(raw, &previous) == nil {
			stsTokenClaims.CallChain = append(previous, result.Client.ID)
		}
	} else {
		issuerAlias, ok := a.GetIssuerAlias(subjectIssuer)
		if !ok {
			return nil, fmt.Errorf("issuer alias for %q not found", subjectIssuer)
		}
		stsTokenClaims.IDP = string(subjectIssuer)
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
