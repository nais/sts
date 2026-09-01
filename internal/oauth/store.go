package oauth

import (
	"context"

	"github.com/go-jose/go-jose/v4"
)

type ClientID string

type ClientStore interface {
	GetClient(context.Context, ClientID) (*OAuthClient, error)
	AuthorizeTarget(clientID ClientID, target ClientID) error
}

type KeyStore interface {
	Signer(context.Context) (jose.Signer, error)
	PublicKeys(context.Context) (*jose.JSONWebKeySet, error)
}
