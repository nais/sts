package oauth

import (
	"context"
	"errors"

	"github.com/nais/sts/internal/jwk"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	ErrRegistrationUnauthorized = errors.New("client owned by another issuer")
	ErrRegistrationConflict     = errors.New("registration conflicts with existing client")
	ErrImmutableFieldsChanged   = errors.New("immutable fields differ")
	ErrClientNotFound           = errors.New("client not found")
	ErrTargetUnauthorized       = errors.New("no authorization policy")
)

type ClientStore interface {
	AuthorizeTarget(ctx context.Context, consumer ClientID, target Target) (Roles, error)
	Delete(ctx context.Context, clientID ClientID, authoritativeIssuer string) error
	Get(ctx context.Context, claims *AccessTokenClaims) (*Client, error)
	Save(ctx context.Context, client *Client, policies []AuthorizationPolicy, authoritativeIssuer string) error
}

type KeyStore interface {
	Signer() (*jwk.Signer, error)
	PublicKeys() (*jwk.KeySet, error)
	oidc.KeySet
}
