package oauth

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type (
	ClientID string
	Name     string
	Roles    []string
)

var namePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]*[a-z0-9])?$`)

func (n Name) Validate() error {
	if !namePattern.MatchString(string(n)) {
		return fmt.Errorf("invalid name")
	}
	return nil
}

func (c ClientID) Validate() error {
	for _, part := range strings.Split(string(c), ":") {
		if err := Name(part).Validate(); err != nil {
			return fmt.Errorf("invalid client ID")
		}
	}
	return nil
}

type ClientStore interface {
	AuthorizeTarget(ctx context.Context, clientID ClientID, target Target) (Roles, error)
	Delete(ctx context.Context, clientID ClientID) error
	Get(ctx context.Context, clientAuthClaims *AccessTokenClaims) (*Client, error)
	GetByID(ctx context.Context, clientID ClientID) (*Client, error)
	Save(ctx context.Context, client *Client, policies []AuthorizationPolicy) error
}

type KeyStore interface {
	Signer() (jose.Signer, error)
	PublicKeys() (*jose.JSONWebKeySet, error)
	oidc.KeySet
}
