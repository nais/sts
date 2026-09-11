package registration

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type ClientRegistratorConfig struct {
	Issuer        string   `json:"issuer" yaml:"issuer"`
	Subject       string   `json:"subject" yaml:"subject"`
	ClientJwksUri string   `json:"client_jwks_uri" yaml:"clientJwksUri"`
	RequiredAlgs  []string `json:"required_algs" yaml:"requiredAlgs"`
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
		if err := validateURL(registrator.Issuer); err != nil {
			return fmt.Errorf("registrator %d issuer: %w", i, err)
		}
		if err := validateURL(registrator.ClientJwksUri); err != nil {
			return fmt.Errorf("registrator %d client JWKS URI: %w", i, err)
		}
		if len(registrator.RequiredAlgs) == 0 {
			return fmt.Errorf("registrator %d required algorithms must not be empty", i)
		}
	}
	return nil
}

func validateURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("must be an absolute URL")
	}
	isLoopback := strings.EqualFold(parsed.Hostname(), "localhost") || net.ParseIP(parsed.Hostname()).IsLoopback()
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLoopback) {
		return fmt.Errorf("must use https, except for localhost or loopback http URLs")
	}
	return nil
}
