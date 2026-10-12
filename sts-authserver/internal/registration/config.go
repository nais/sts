package registration

import (
	"fmt"

	"github.com/nais/sts/internal/oauth"
)

type ClientRegistratorConfig struct {
	Issuer        string   `yaml:"issuer"`
	Subject       string   `yaml:"subject"`
	ClientJwksUri string   `yaml:"clientJwksUri"`
	RequiredAlgs  []string `yaml:"requiredAlgs"`
}

type ClientRegistrators []*ClientRegistratorConfig

func (r ClientRegistrators) Validate() error {
	for i, registrator := range r {
		if registrator == nil {
			return fmt.Errorf("registrator %d must not be null", i)
		}
		if registrator.Subject == "" {
			return fmt.Errorf("registrator %d subject must not be empty", i)
		}
		if err := oauth.ValidateSecureURL(registrator.Issuer); err != nil {
			return fmt.Errorf("registrator %d issuer: %w", i, err)
		}
		if err := oauth.ValidateSecureURL(registrator.ClientJwksUri); err != nil {
			return fmt.Errorf("registrator %d client JWKS URI: %w", i, err)
		}
		if err := oauth.ValidateSigningAlgorithms(registrator.RequiredAlgs); err != nil {
			return fmt.Errorf("registrator %d required algorithms: %w", i, err)
		}
	}
	return nil
}
