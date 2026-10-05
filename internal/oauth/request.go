package oauth

import (
	"net/url"
	"strings"

	"github.com/nais/sts/internal/errs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenRequest interface {
	GrantType() oidc.GrantType
	Target() (Target, error)
	Validate() error
	GetClientAuthCredentials() *ClientAuthCredentials
}

var (
	_ TokenRequest = (*ClientCredentialsRequest)(nil)
	_ TokenRequest = (*TokenExchangeRequest)(nil)
)

type ClientAuthCredentials struct {
	ClientAssertion     string
	ClientAssertionType string
}

func parseClientAuthCredentials(form url.Values) ClientAuthCredentials {
	return ClientAuthCredentials{
		ClientAssertion:     form.Get("client_assertion"),
		ClientAssertionType: form.Get("client_assertion_type"),
	}
}

func (c *ClientAuthCredentials) Validate() error {
	if c.ClientAssertion == "" || c.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return errs.InvalidRequest(nil, "client_assertion must be provided and be of type %s", oidc.ClientAssertionTypeJWTAssertion)
	}
	return nil
}

func (c *ClientAuthCredentials) GetClientAuthCredentials() *ClientAuthCredentials {
	return c
}

type ClientCredentialsRequest struct {
	ClientAuthCredentials
	Scope []string
}

func parseClientCredentialsRequest(form url.Values) *ClientCredentialsRequest {
	// TODO: consider rejecting repeated parameters, as RFC 6749 section 3.1 requires.
	//  form.Get uses the first value and ignores the rest.
	return &ClientCredentialsRequest{
		ClientAuthCredentials: parseClientAuthCredentials(form),
		Scope:                 strings.Fields(form.Get("scope")),
	}
}

func (c *ClientCredentialsRequest) GrantType() oidc.GrantType {
	return oidc.GrantTypeClientCredentials
}

func (c *ClientCredentialsRequest) Target() (Target, error) {
	if len(c.Scope) != 1 {
		return nil, errs.InvalidTarget(nil, "scope must contain exactly one target scope")
	}
	return TargetScope(c.Scope[0]), nil
}

func (c *ClientCredentialsRequest) Validate() error {
	if err := c.ClientAuthCredentials.Validate(); err != nil {
		return err
	}
	_, err := c.Target()
	return err
}

type TokenExchangeRequest struct {
	ClientAuthCredentials
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	RequestedTokenType string
	Audience           string
}

func parseTokenExchangeRequest(form url.Values) *TokenExchangeRequest {
	// TODO: consider rejecting repeated parameters, as RFC 6749 section 3.1 requires.
	//  form.Get uses the first value and ignores the rest.
	return &TokenExchangeRequest{
		ClientAuthCredentials: parseClientAuthCredentials(form),
		SubjectToken:          form.Get("subject_token"),
		SubjectTokenType:      form.Get("subject_token_type"),
		ActorToken:            form.Get("actor_token"),
		RequestedTokenType:    form.Get("requested_token_type"),
		Audience:              form.Get("audience"),
	}
}

func (t *TokenExchangeRequest) GrantType() oidc.GrantType {
	return oidc.GrantTypeTokenExchange
}

func (t *TokenExchangeRequest) Target() (Target, error) {
	if t.Audience == "" {
		return nil, errs.InvalidTarget(nil, "audience must contain exactly one audience")
	}
	return TargetAudience(t.Audience), nil
}

func (t *TokenExchangeRequest) Validate() error {
	if err := t.ClientAuthCredentials.Validate(); err != nil {
		return err
	}
	if t.ActorToken != "" {
		return errs.InvalidRequest(nil, "actor_token is not supported")
	}
	if t.SubjectToken == "" {
		return errs.InvalidRequest(nil, "subject_token missing")
	}
	if t.SubjectTokenType != string(oidc.JWTTokenType) {
		return errs.InvalidRequest(nil, "subject_token_type must be %s", oidc.JWTTokenType)
	}
	if t.RequestedTokenType != string(oidc.AccessTokenType) {
		return errs.InvalidRequest(nil, "requested_token_type must be %s", oidc.AccessTokenType)
	}
	_, err := t.Target()
	return err
}

type Target interface {
	GetValue() string
	GetType() string
	AsAudience() oidc.Audience
}

type (
	TargetScope    string
	TargetAudience string
)

var (
	_ Target = (*TargetScope)(nil)
	_ Target = (*TargetAudience)(nil)
)

func (t TargetAudience) GetValue() string {
	return string(t)
}

func (t TargetAudience) GetType() string {
	return "audience"
}

func (t TargetAudience) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}

func (t TargetScope) GetValue() string {
	return string(t)
}

func (t TargetScope) GetType() string {
	return "scope"
}

func (t TargetScope) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}
