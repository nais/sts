package oauth

import (
	"github.com/nais/sts/internal/database/sqlgen"
)

type Client struct {
	sqlgen.KubernetesClient
	// AllowedScopes is "static access", i.e. doesn't require the existence of a target client ID
}
