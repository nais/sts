package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

type AccessTokenResponse struct {
	AccessToken     string                   `json:"access_token"`
	IssuedTokenType oidc.TokenType           `json:"issued_token_type,omitempty"`
	TokenType       string                   `json:"token_type"`
	ExpiresIn       uint64                   `json:"expires_in,omitempty"`
	Scopes          oidc.SpaceDelimitedArray `json:"scope,omitempty"`
}

type ClientAuthCredentials struct {
	ClientID            string `schema:"client_id"`
	ClientAssertion     string `schema:"client_assertion"` // JWT
	ClientAssertionType string `schema:"client_assertion_type"`
}

type TokenRequest interface {
	oidc.TokenRequest
	Target() (Target, error)
	Validate() error
	GetClientAuthCredentials() *ClientAuthCredentials
}

var _ TokenRequest = (*ClientCredentialsRequest)(nil)
var _ TokenRequest = (*TokenExchangeRequest)(nil)

type ClientCredentialsRequest struct {
	oidc.ClientCredentialsRequest
}

type TokenExchangeRequest struct {
	oidc.TokenExchangeRequest
	*ClientAuthCredentials
}

func (t *TokenExchangeRequest) GetClientAuthCredentials() *ClientAuthCredentials {
	return t.ClientAuthCredentials
}

func (c *ClientCredentialsRequest) GetClientAuthCredentials() *ClientAuthCredentials {
	return &ClientAuthCredentials{
		ClientID:            c.ClientID,
		ClientAssertion:     c.ClientAssertion,
		ClientAssertionType: c.ClientAssertionType,
	}
}

func (c *ClientAuthCredentials) Validate() error {
	if c.ClientAssertion == "" || c.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return oidc.ErrInvalidRequest().WithDescription("client_assertion must be provided and be of type %s", oidc.ClientAssertionTypeJWTAssertion)
	}
	return nil
}

func (c *ClientCredentialsRequest) Target() (Target, error) {
	if len(c.Scope) != 1 {
		return nil, oidc.ErrInvalidTarget().WithDescription("scope must contain exactly one target scope")
	}
	return targetScope(c.Scope[0]), nil
}

func (t *TokenExchangeRequest) Target() (Target, error) {
	if len(t.Audience) != 1 {
		return nil, oidc.ErrInvalidTarget().WithDescription("audience must contain exactly one audience")
	}
	return targetAudience(t.Audience[0]), nil
}

func (c *ClientCredentialsRequest) Validate() error {
	ca := &ClientAuthCredentials{
		ClientID:            c.ClientID,
		ClientAssertion:     c.ClientAssertion,
		ClientAssertionType: c.ClientAssertionType,
	}
	if err := ca.Validate(); err != nil {
		return err
	}
	if len(c.Scope) != 1 {
		return oidc.ErrInvalidTarget().WithDescription("scope must contain exactly one target scope")
	}
	return nil
}

func (t *TokenExchangeRequest) Validate() error {
	if err := t.ClientAuthCredentials.Validate(); err != nil {
		return err
	}
	if t.ActorToken != "" {
		return oidc.ErrInvalidRequest().WithDescription("actor_token is not supported")
	}
	if t.SubjectToken == "" {
		return oidc.ErrInvalidRequest().WithDescription("subject_token missing")
	}
	if t.SubjectTokenType != oidc.JWTTokenType {
		return oidc.ErrInvalidRequest().WithDescription("subject_token_type must be %s", oidc.JWTTokenType)
	}
	if t.RequestedTokenType != oidc.AccessTokenType {
		return oidc.ErrInvalidRequest().WithDescription("requested_token_type must be %s", oidc.AccessTokenType)
	}
	if len(t.Audience) != 1 {
		return oidc.ErrInvalidTarget().WithDescription("audience must contain exactly one audience")
	}

	return nil
}

func (c *ClientCredentialsRequest) GrantType() oidc.GrantType {
	return c.ClientCredentialsRequest.GrantType
}

func (t *TokenExchangeRequest) GrantType() oidc.GrantType {
	return t.TokenExchangeRequest.GrantType
}

type Target interface {
	GetValue() string
	GetType() string
	AsAudience() oidc.Audience
}

type targetScope string
type targetAudience string

func (t targetAudience) GetValue() string {
	return string(t)
}

func (t targetAudience) GetType() string {
	return "audience"
}

func (t targetAudience) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}

func (t targetScope) GetValue() string {
	return string(t)
}

func (t targetScope) GetType() string {
	return "scope"
}

func (t targetScope) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}

var _ Target = (*targetScope)(nil)
var _ Target = (*targetAudience)(nil)
