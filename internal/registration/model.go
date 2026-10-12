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

func (r ClientRegistration) validate() error {
	if strings.TrimSpace(r.SoftwareStatement) == "" {
		return errors.New("software_statement is required")
	}
	if len(r.SoftwareStatement) > maxSoftwareStatementLength {
		return errors.New("software_statement is too long")
	}
	return nil
}

type ClientRegistrationResponse struct {
	ClientRegistration
	ClientID string `json:"client_id"`
}

type SoftwareStatement struct {
	ClientId              string                `json:"client_id"`
	Workload              Workload              `json:"workload"`
	AuthorizationPolicies []AuthorizationPolicy `json:"authorization_policies"`
}

type Workload struct {
	Environment string `json:"environment"`
	Issuer      string `json:"issuer"`
	Namespace   string `json:"namespace"`
	Name        string `json:"workload"`
}

type AuthorizationPolicy struct {
	Consumer string   `json:"consumer"`
	Roles    []string `json:"roles"`
}

// SetSignatureAlgorithm no-op, required to satisfy the oidc.ClaimsSignature interface when using oidc.CheckSignature
func (s SoftwareStatement) SetSignatureAlgorithm(_ jose.SignatureAlgorithm) {}

func (s SoftwareStatement) validate() error {
	clientID := oauth.ClientID(s.ClientId)
	if err := clientID.Validate(); err != nil {
		return fmt.Errorf("client_id: %w", err)
	}
	// TODO: decide whether client_id must be derived from the workload identity or remain independent.
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
		consumer := oauth.ClientID(policy.Consumer)
		if err := consumer.Validate(); err != nil {
			return fmt.Errorf("authorization policy %d consumer: %w", i, err)
		}
		key := policy.Consumer
		if _, ok := policies[key]; ok {
			return fmt.Errorf("authorization policy %d is duplicated", i)
		}
		policies[key] = struct{}{}

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
