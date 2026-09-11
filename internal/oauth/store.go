package oauth

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type (
	ClientID string
	Roles    []string
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z](?:[A-Za-z0-9:-]*[A-Za-z0-9])?$`)

func (c ClientID) Validate() error {
	if !clientIDPattern.MatchString(string(c)) {
		return fmt.Errorf("invalid client ID")
	}
	return nil
}

type ClientStore interface {
	AuthorizeTarget(ctx context.Context, clientID ClientID, target Target) (Roles, error)
	Delete(ctx context.Context, clientID ClientID) error
	Get(ctx context.Context, clientAuthClaims *AccessTokenClaims) (*Client, error)
	Save(ctx context.Context, client *Client, policies []AuthorizationPolicy) error
}

type KeyStore interface {
	Signer() (jose.Signer, error)
	PublicKeys() (*jose.JSONWebKeySet, error)
	oidc.KeySet
}
