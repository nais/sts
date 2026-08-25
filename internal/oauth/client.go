package oauth

import (
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Client struct {
	id               string   `yaml:"-"`
	WorkloadIssuer   string   `yaml:"workloadIssuer"`
	WorkloadSubject  string   `yaml:"workloadSubject"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

func (c *Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *Client) allowsAudience(audience string) bool {
	return slices.Contains(c.AllowedAudiences, audience)
}

func (c *Client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *Client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodPrivateKeyJWT }
func (c *Client) ClockSkew() time.Duration            { return 0 }
func (c *Client) DevMode() bool                       { return false }
func (c *Client) GetID() string                       { return c.id }
func (c *Client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeClientCredentials, oidc.GrantTypeTokenExchange}
}
func (c *Client) IDTokenLifetime() time.Duration       { return 0 }
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *Client) IsScopeAllowed(string) bool           { return true }
func (c *Client) LoginURL(string) string               { return "" }
func (c *Client) PostLogoutRedirectURIs() []string     { return nil }
func (c *Client) RedirectURIs() []string               { return nil }
func (c *Client) ResponseTypes() []oidc.ResponseType   { return nil }

func (c *Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func([]string) []string { return nil }
}
