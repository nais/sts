package oauth

import (
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Zitadel token validation errors that are safe to show to the caller.
var publicTokenErrors = []error{
	oidc.ErrParse,
	oidc.ErrIssuerInvalid,
	oidc.ErrSubjectMissing,
	oidc.ErrSignatureMissing,
	oidc.ErrSignatureMultiple,
	oidc.ErrSignatureUnsupportedAlg,
	oidc.ErrSignatureInvalidPayload,
	// TODO: zitadel also returns ErrSignatureInvalid when the JWKS cannot be fetched.
	// An issuer outage then returns 400 "invalid signature" and logs a warning, not an error.
	oidc.ErrSignatureInvalid,
	oidc.ErrExpired,
	oidc.ErrIatMissing,
	oidc.ErrIatInFuture,
}

// WrapError turns err into a response error of type base.
// The caller sees prefix, plus the reason from err if that reason is safe to show.
// The rest of err is logged but not returned.
//
// good example: the caller sees "prefix: token expired", and cause is only logged
//
//	WrapError(base, "prefix", oidc.ErrInvalidClient().WithDescription("token expired").WithParent(cause))
//
// bad example: the "issuer ..." text is not shown and not logged
//
//	WrapError(base, "prefix", fmt.Errorf("issuer %q: %w", iss, oidcErr))
func WrapError(base *oidc.Error, prefix string, err error) *oidc.Error {
	if base.ErrorType == oidc.ServerError {
		return base.WithParent(err).WithDescription("%s", prefix)
	}
	if e, ok := clientError(err); ok {
		return base.WithParent(e.Parent).WithDescription("%s: %s", prefix, e.Description)
	}
	base = base.WithParent(err)
	for _, public := range publicTokenErrors {
		if errors.Is(err, public) {
			return base.WithDescription("%s: %s", prefix, public)
		}
	}
	return base.WithDescription("%s", prefix)
}

// clientError returns the oidc.Error in err if its description is safe to return.
func clientError(err error) (*oidc.Error, bool) {
	e, ok := errors.AsType[*oidc.Error](err)
	return e, ok && e.ErrorType != oidc.ServerError
}
