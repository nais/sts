package oauth

import (
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func NewServer(issuer string, endpoints *op.Endpoints) (http.Handler, error) {
	// TODO: Add a proper storage implementation for clients and tokens.
	provider, err := op.NewProvider(
		&op.Config{},
		newStorage(),
		op.StaticIssuer(issuer),
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, err
	}

	server := op.NewLegacyServer(provider, *endpoints)
	return op.RegisterServer(server, *endpoints), nil
}
