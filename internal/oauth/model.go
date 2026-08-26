package oauth

import (
	"context"
	"slices"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type OAuthClient struct {
	WorkloadIssuer   string   `yaml:"workloadIssuer"`
	WorkloadSubject  string   `yaml:"workloadSubject"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

type TrustedIssuer struct {
	Issuer   string
	JwksUrl  string
	verifier TokenVerifier
}

// TODO: use AccessTokenClaims to get all claims
func (t *TrustedIssuer) Verify(ctx context.Context, token string) (*oidc.TokenClaims, error) {
	return t.Verify(ctx, token)
}

type AuthorizationServer struct {
	ClientAuthIssuers    []TrustedIssuer
	TokenExchangeIssuers []TrustedIssuer
}

type TokenExchangeRequest struct {
	oidc.TokenExchangeRequest
}

func (t *TokenExchangeRequest) GrantType() oidc.GrantType {
	return t.GrantType()
}

type ClientCredentialsRequest struct {
	oidc.ClientCredentialsRequest
}

func (t *ClientCredentialsRequest) GrantType() oidc.GrantType {
	return t.GrantType()
}

func (a *AuthorizationServer) Authorize(_ context.Context, request oidc.TokenRequest, client OAuthClient) error {
	switch r := request.(type) {
	case *ClientCredentialsRequest:
		if !slices.Contains(client.AllowedAudiences, r.Scope[0]) {
			return oidc.ErrInvalidTarget().WithDescription("requested scope is not allowed for this client")
		}
	case *TokenExchangeRequest:
		if !slices.Contains(client.AllowedAudiences, r.Audience[0]) {
			return oidc.ErrInvalidTarget().WithDescription("requested audience is not allowed for this client")
		}
	default:
		return oidc.ErrInvalidRequest().WithDescription("unsupported grant type")
	}
	return nil
}
