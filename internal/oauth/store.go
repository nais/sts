package oauth

import (
	"context"

	"github.com/go-jose/go-jose/v4"
)

type ClientID string
type Roles []string

type ClientStore interface {
	Get(ctx context.Context, clientAuthClaims *AccessTokenClaims) (*Client, error)
	Save(ctx context.Context, client *Client) error
	AuthorizeTarget(ctx context.Context, clientID ClientID, target Target) (Roles, error)
}

type KeyStore interface {
	Signer(ctx context.Context) (jose.Signer, error)
	PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error)
}
