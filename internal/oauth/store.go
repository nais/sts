package oauth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type ClientID string

type ClientStore struct {
	Clients map[ClientID]*OAuthClient
}

type KeyStore struct {
	jose.JSONWebKeySet
}

func (s ClientStore) AuthorizeTarget(client *OAuthClient, target Target) error {
	if client.allowsAudience(target.GetValue()) {
		return nil
	}
	return oidc.ErrInvalidTarget().WithDescription("requested %s is not allowed for this client", target.GetType())
}
