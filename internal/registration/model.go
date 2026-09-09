package registration

import (
	"errors"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/oauth"
)

const (
	maxClientNameLength        = 256
	maxSoftwareStatementLength = 32 << 10
)

type ClientRegistration struct {
	ClientName        string `json:"client_name"`
	SoftwareStatement string `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type SoftwareStatement struct {
	ClientId              string                      `json:"client_id"`
	Workload              Workload                    `json:"workload"`
	AuthorizationPolicies []oauth.AuthorizationPolicy `json:"authorization_policies"`
}

// SetSignatureAlgorithm no-op, required to satisfy the oidc.ClaimsSignature interface when using oidc.CheckSignature
func (s SoftwareStatement) SetSignatureAlgorithm(_ jose.SignatureAlgorithm) {}

// TODO: validate and sanitize for db insert
func (s SoftwareStatement) validate() error {
	return nil
}

type Workload struct {
	Environment string `json:"environment"`
	Issuer      string `json:"issuer"`
	Namespace   string `json:"namespace"`
	Name        string `json:"workload"`
}

type AuthorizationPolicy struct {
	Owner    oauth.ClientID `json:"owner"`
	Consumer oauth.ClientID `json:"consumer"`
	Roles    oauth.Roles    `json:"roles"`
}

func (r ClientRegistration) validate() error {
	if strings.TrimSpace(r.ClientName) == "" {
		return errors.New("client_name is required")
	}
	if len(r.ClientName) > maxClientNameLength {
		return errors.New("client_name is too long")
	}
	if strings.TrimSpace(r.SoftwareStatement) == "" {
		return errors.New("software_statement is required")
	}
	if len(r.SoftwareStatement) > maxSoftwareStatementLength {
		return errors.New("software_statement is too long")
	}
	return nil
}
