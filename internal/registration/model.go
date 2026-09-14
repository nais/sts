package registration

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/oauth"
)

const (
	maxSoftwareStatementLength = 32 << 10
	maxRoleLength              = 255
)

type ClientRegistration struct {
	SoftwareStatement string `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	// TODO: review whether registration response metadata should be populated or removed.
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

func (s SoftwareStatement) validate() error {
	clientID := oauth.ClientID(s.ClientId)
	if err := clientID.Validate(); err != nil {
		return fmt.Errorf("client_id: %w", err)
	}
	if err := oauth.Name(s.Workload.Environment).Validate(); err != nil {
		return fmt.Errorf("workload environment: %w", err)
	}
	if err := oauth.ValidateSecureURL(s.Workload.Issuer); err != nil {
		return fmt.Errorf("workload issuer: %w", err)
	}
	if err := oauth.Name(s.Workload.Namespace).Validate(); err != nil {
		return fmt.Errorf("workload namespace: %w", err)
	}
	if err := oauth.Name(s.Workload.Name).Validate(); err != nil {
		return fmt.Errorf("workload name: %w", err)
	}

	policies := make(map[string]struct{}, len(s.AuthorizationPolicies))
	for i, policy := range s.AuthorizationPolicies {
		if policy.Owner != clientID {
			return fmt.Errorf("authorization policy %d owner must equal client_id", i)
		}
		if err := policy.Consumer.Validate(); err != nil {
			return fmt.Errorf("authorization policy %d consumer: %w", i, err)
		}
		key := string(policy.Consumer)
		if _, ok := policies[key]; ok {
			return fmt.Errorf("authorization policy %d is duplicated", i)
		}
		policies[key] = struct{}{}

		if len(policy.Roles) == 0 {
			return fmt.Errorf("authorization policy %d roles must not be empty", i)
		}
		roles := make(map[string]struct{}, len(policy.Roles))
		for j, role := range policy.Roles {
			if len(role) > maxRoleLength {
				return fmt.Errorf("authorization policy %d role %d is too long", i, j)
			}
			if err := oauth.Name(role).Validate(); err != nil {
				return fmt.Errorf("authorization policy %d role %d is invalid", i, j)
			}
			if _, ok := roles[role]; ok {
				return fmt.Errorf("authorization policy %d role %q is duplicated", i, role)
			}
			roles[role] = struct{}{}
		}
	}
	return nil
}

type Workload struct {
	Environment string `json:"environment"`
	Issuer      string `json:"issuer"`
	Namespace   string `json:"namespace"`
	Name        string `json:"workload"`
}

func (r ClientRegistration) validate() error {
	if strings.TrimSpace(r.SoftwareStatement) == "" {
		return errors.New("software_statement is required")
	}
	if len(r.SoftwareStatement) > maxSoftwareStatementLength {
		return errors.New("software_statement is too long")
	}
	return nil
}
