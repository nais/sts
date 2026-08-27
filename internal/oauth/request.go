package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

type TokenRequest interface {
	oidc.TokenRequest
	Target() (Target, error)
	Validate() error
}

var _ TokenRequest = (*ClientCredentialsRequest)(nil)
var _ TokenRequest = (*TokenExchangeRequest)(nil)

type ClientCredentialsRequest struct {
	oidc.ClientCredentialsRequest
}

type TokenExchangeRequest struct {
	oidc.TokenExchangeRequest
}

func (t *ClientCredentialsRequest) Target() (Target, error) {
	if len(t.Scope) != 1 {
		return nil, oidc.ErrInvalidTarget().WithDescription("scope must contain exactly one target scope")
	}
	return targetScope(t.Scope[0]), nil
}

func (t *TokenExchangeRequest) Target() (Target, error) {
	if len(t.Audience) != 1 {
		return nil, oidc.ErrInvalidTarget().WithDescription("audience must contain exactly one audience")
	}
	return targetAudience(t.Audience[0]), nil
}

func (t *ClientCredentialsRequest) Validate() error {
	if len(t.Scope) != 1 {
		return oidc.ErrInvalidTarget().WithDescription("scope must contain exactly one target scope")
	}
	return nil
}

func (t *TokenExchangeRequest) Validate() error {
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

func (t *ClientCredentialsRequest) GrantType() oidc.GrantType {
	return t.ClientCredentialsRequest.GrantType
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
