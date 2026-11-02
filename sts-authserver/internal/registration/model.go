package registration

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/oauth"
)

const (
	maxSoftwareStatementLength = 32 << 10
	maxRoleLength              = 255
)

type SoftwareStatement struct {
	api.SoftwareStatement
}

// SetSignatureAlgorithm no-op, required to satisfy the oidc.ClaimsSignature interface when using oidc.CheckSignature
func (s SoftwareStatement) SetSignatureAlgorithm(_ jose.SignatureAlgorithm) {}

func (s SoftwareStatement) validate() error {
	if err := validateClient(s.Client); err != nil {
		return fmt.Errorf("client: %w", err)
	}

	policies := make(map[api.Client]struct{}, len(s.AuthorizationPolicies))
	// TODO: do we really need all this validation?
	for i, policy := range s.AuthorizationPolicies {
		if err := validateClient(policy.Consumer); err != nil {
			return fmt.Errorf("authorization policy %d consumer: %w", i, err)
		}
		key := policy.Consumer
		if _, ok := policies[key]; ok {
			return fmt.Errorf("authorization policy %d is duplicated", i)
		}
		policies[key] = struct{}{}

		roles := make(map[string]struct{}, len(policy.Roles))
		for j, role := range policy.Roles {
			// TODO: we could move role validation out to CRDs?
			if len(role) > maxRoleLength {
				return fmt.Errorf("authorization policy %d role %d is too long", i, j)
			}

			if err := oauth.Name(role).Validate(); err != nil {
				return fmt.Errorf("authorization policy %d role %d is invalid", i, j)
			}

			// TODO: we could automatically de-duplicate roles instead of erroring
			if _, ok := roles[role]; ok {
				return fmt.Errorf("authorization policy %d role %q is duplicated", i, role)
			}
			roles[role] = struct{}{}
		}
	}
	return nil
}

func validateClient(client api.Client) error {
	if err := oauth.Name(client.Namespace).Validate(); err != nil {
		return fmt.Errorf("namespace: %w", err)
	}
	if err := oauth.Name(client.Name).Validate(); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	return nil
}
