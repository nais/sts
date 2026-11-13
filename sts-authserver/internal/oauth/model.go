package oauth

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nais/sts/internal/errs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Roles []string

type Name string

var namePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]*[a-z0-9])?$`)

func (n Name) Validate() error {
	if !namePattern.MatchString(string(n)) {
		return fmt.Errorf("invalid name")
	}
	return nil
}

// ClientID identifies a client as environment:namespace:name.
type ClientID string

func NewClientID(environment, namespace, name Name) ClientID {
	return ClientID(string(environment) + ":" + string(namespace) + ":" + string(name))
}

func (c ClientID) Validate() error {
	parts := strings.Split(string(c), ":")
	if len(parts) != 3 {
		return fmt.Errorf("invalid client ID: got %d parts, want environment:namespace:name", len(parts))
	}
	for _, part := range parts {
		if err := Name(part).Validate(); err != nil {
			return fmt.Errorf("invalid client ID: part %q: %w", part, err)
		}
	}
	return nil
}

type Client struct {
	ID                  ClientID
	Issuer              string
	Environment         string
	Namespace           string
	Name                string
	AuthorizationPolicy AuthorizationPolicy
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type AuthorizationPolicy struct {
	AllowAll          bool               `json:"allow_all,omitempty"`
	AllowedNamespaces []string           `json:"allowed_namespaces,omitempty"`
	AllowedScopes     []string           `json:"allowed_scopes,omitempty"`
	Clients           []AuthorizedClient `json:"clients,omitempty"`
}

type AuthorizedClient struct {
	ClientID ClientID `json:"client_id"`
	Roles    Roles    `json:"roles,omitempty"`
}

type Target interface {
	// TODO: should we use ClientID type here?
	GetValue() string
	GetType() string
	AsAudience() oidc.Audience
}

type TargetAudience string

var _ Target = (*TargetAudience)(nil)

func (t TargetAudience) GetValue() string {
	return string(t)
}

func (t TargetAudience) GetType() string {
	return "audience"
}

func (t TargetAudience) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}

type TargetScope string

var _ Target = (*TargetScope)(nil)

func (t TargetScope) GetValue() string {
	return string(t)
}

func (t TargetScope) GetType() string {
	return "scope"
}

func (t TargetScope) AsAudience() oidc.Audience {
	return oidc.Audience{string(t)}
}

type TokenRequest interface {
	GrantType() oidc.GrantType
	Target() (Target, error)
	Validate() error
	GetClientAuthCredentials() *ClientAuthCredentials
}

type ClientAuthCredentials struct {
	ClientAssertion     string
	ClientAssertionType string
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

var _ TokenRequest = (*ClientCredentialsRequest)(nil)

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

var _ TokenRequest = (*TokenExchangeRequest)(nil)

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

type AccessTokenResponse struct {
	AccessToken     string                   `json:"access_token"`
	IssuedTokenType oidc.TokenType           `json:"issued_token_type,omitempty"`
	TokenType       string                   `json:"token_type"`
	ExpiresIn       uint64                   `json:"expires_in,omitempty"`
	Scopes          oidc.SpaceDelimitedArray `json:"scope,omitempty"`
}
