package registration

import (
	"errors"

	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var errIssuerMismatch = errors.New("workload issuer mismatch")

// Error codes from RFC 7591 section 3.2.2 and RFC 6750 section 3.1.
func errInvalidClientMetadata() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_client_metadata"}
}

func errInvalidSoftwareStatement() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_software_statement"}
}

func errUnapprovedSoftwareStatement() *oidc.Error {
	return &oidc.Error{ErrorType: "unapproved_software_statement"}
}

func errInvalidToken() *oidc.Error {
	return &oidc.Error{ErrorType: "invalid_token"}
}

func httpError(status int, base *oidc.Error, prefix string, err error) error {
	return op.NewStatusError(oauth.WrapError(base, prefix, err), status)
}
