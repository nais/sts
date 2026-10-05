package oauth

import (
	"encoding/json"
	"maps"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/errs"
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
		subjectIssuer := Issuer(result.SubjectTokenClaims.Issuer)
		stsTokenClaims.Actor = &ActorClaims{
			ClientID: result.Client.ID,
		}

		// ignore existing `act` claim for externally issued subject tokens
		if subjectIssuer == issuer {
			if raw, ok := subjectTokenClaims["act"]; ok {
				// preserve the chain of `act` claims
				stsTokenClaims.Actor.Actor = raw
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

type KubernetesClaims struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}

func (a *AccessTokenClaims) Kubernetes() (*KubernetesClaims, error) {
	raw, ok := a.Claims["kubernetes.io"]
	if !ok {
		return nil, errs.NewErrorDescription("kubernetes.io claim is missing")
	}

	var kubernetes KubernetesClaims
	if err := json.Unmarshal(raw, &kubernetes); err != nil {
		return nil, errs.WrapErrorDescription(err, "kubernetes.io claim is malformed")
	}

	if kubernetes.Namespace == "" || kubernetes.ServiceAccount.Name == "" {
		return nil, errs.NewErrorDescription("kubernetes.io claim has no namespace or service account name")
	}
	return &kubernetes, nil
}
