package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

type AccessTokenResponse struct {
	AccessToken     string                   `json:"access_token"`
	IssuedTokenType oidc.TokenType           `json:"issued_token_type,omitempty"`
	TokenType       string                   `json:"token_type"`
	ExpiresIn       uint64                   `json:"expires_in,omitempty"`
	Scopes          oidc.SpaceDelimitedArray `json:"scope,omitempty"`
}
