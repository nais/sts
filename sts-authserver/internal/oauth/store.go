package oauth

import (
	"context"
	"errors"

	"github.com/nais/sts/internal/jwk"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	ErrRegistrationUnauthorized = errors.New("client owned by another issuer")
	ErrClientNotFound           = errors.New("client not found")
	ErrTargetUnauthorized       = errors.New("no authorization policy")
)

type ClientStore interface {
	AuthorizeTarget(ctx context.Context, consumer *Client, target ClientID) (Roles, error)
	Delete(ctx context.Context, clientID ClientID, authoritativeIssuer string) error
	Get(issuer, namespace, name string) (*Client, error)
	GetByID(clientID ClientID) (*Client, error)
	Save(ctx context.Context, client *Client, authoritativeIssuer string) (changed bool, err error)
}

type KeyStore interface {
	Signer() (*jwk.Signer, error)
	PublicKeys() (*jwk.KeySet, error)
	oidc.KeySet
}
