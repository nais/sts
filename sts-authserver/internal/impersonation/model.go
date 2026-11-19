package impersonation

import (
	"github.com/nais/sts/internal/jwt"
)

type Request struct {
}

type AuthenticatedUser struct {
	Claims *jwt.AccessTokenClaims
}
