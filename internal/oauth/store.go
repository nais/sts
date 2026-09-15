package oauth

import (
	"context"
	"errors"
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
	for part := range strings.SplitSeq(string(c), ":") {
		if err := Name(part).Validate(); err != nil {
			return fmt.Errorf("invalid client ID")
		}
	}
	return nil
}

type ClientStore interface {
	AuthorizeTarget(ctx context.Context, clientID ClientID, target Target) (Roles, error)
	Delete(ctx context.Context, clientID ClientID, authoritativeIssuer string) error
	Get(ctx context.Context, clientAuthClaims *AccessTokenClaims) (*Client, error)
	Save(ctx context.Context, client *Client, policies []AuthorizationPolicy, authoritativeIssuer string) error
}

var ErrRegistrationUnauthorized = errors.New("registrator is not authorized for client")
var ErrRegistrationConflict = errors.New("registration conflicts with existing client")

type KeyStore interface {
	Signer() (jose.Signer, error)
	PublicKeys() (*jose.JSONWebKeySet, error)
	oidc.KeySet
}
