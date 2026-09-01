package oauth

import (
	"github.com/nais/sts/internal/database/sqlgen"
)

// TODO: fix to match db model
type OAuthClient struct {
	sqlgen.KubernetesClient
}
