package registration

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/oauth"
)

const maxSoftwareStatementLength = 32 << 10

type SoftwareStatement struct {
	api.SoftwareStatement
}

// SetSignatureAlgorithm no-op, required to satisfy the oidc.ClaimsSignature interface when using oidc.CheckSignature
func (s SoftwareStatement) SetSignatureAlgorithm(_ jose.SignatureAlgorithm) {}

func (s SoftwareStatement) validate() error {
	if err := validateClient(s.Client); err != nil {
		return fmt.Errorf("client: %w", err)
	}

	for i, policy := range s.AuthorizationPolicies {
		if err := validateClient(policy.Consumer); err != nil {
			return fmt.Errorf("authorization policy %d consumer: %w", i, err)
		}
	}

	for i, namespace := range s.ConsumerNamespaces {
		if err := oauth.Name(namespace).Validate(); err != nil {
			return fmt.Errorf("consumer namespace %d: %w", i, err)
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
