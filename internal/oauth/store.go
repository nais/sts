package oauth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AccessControlList struct {
	Allowed []AccessControlListEntry
}

type AccessControlListEntry struct {
	OAuthClient
	Roles []string
}

type ClientID string

type ClientStore struct {
	Clients map[ClientID]*OAuthClient
}

type KeyStore struct {
	jose.JSONWebKeySet
}

func (s ClientStore) AuthorizeTarget(client *OAuthClient, target Target) error {
	err := oidc.ErrInvalidTarget().WithDescription("requested %s is not allowed for this client", target.GetType())
	// Intentional for now to make it compile without logic
	if err == nil {

	}
	return nil
}
