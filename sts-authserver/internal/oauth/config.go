package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwa"
)

type AuthorizationServerConfig struct {
	Issuer                      api.STSIssuer       `yaml:"issuer"`
	ExpectedAudience            string              `yaml:"expectedAudience"`
	Environments                Environments        `yaml:"environments"`
	ClientAuthSigningAlgorithms []string            `yaml:"clientAuthSigningAlgorithms"`
	SubjectTokenIssuers         SubjectTokenIssuers `yaml:"subjectTokenIssuers"`
	MaxClientAuthTokenLifetime  time.Duration       `yaml:"maxClientAuthTokenLifetime"`
	TokenExpiry                 time.Duration       `yaml:"tokenExpiry"`
}

type SubjectTokenIssuers map[TokenIssuer]string

func (s SubjectTokenIssuers) Issuers() []TokenIssuer {
	issuers := make([]TokenIssuer, 0, len(s))
	for issuer := range s {
		issuers = append(issuers, issuer)
	}
	return issuers
}

func (c AuthorizationServerConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer must not be empty")
	}
	if err := validateSecureURL(string(c.Issuer)); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if err := c.Environments.Validate(); err != nil {
		return fmt.Errorf("environments: %w", err)
	}
	if err := jwa.ValidateAlgorithms(c.ClientAuthSigningAlgorithms...); err != nil {
		return fmt.Errorf("client auth signing algorithms: %w", err)
	}
	if c.ExpectedAudience == "" {
		return fmt.Errorf("expected audience must not be empty")
	}
	if c.MaxClientAuthTokenLifetime <= 0 {
		return fmt.Errorf("maximum client auth token lifetime must be positive")
	}
	if c.TokenExpiry <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}
	return nil
}

// Environment maps a human-readable alias to the issuer of one Kubernetes
// cluster. The name is part of every client ID in that cluster, so it must stay
// stable once clients are registered.
type Environment struct {
	Name             Name              `yaml:"name"`
	ClientAuthIssuer TokenIssuer       `yaml:"clientAuthIssuer"`
	Registrator      RegistratorConfig `yaml:"registrator"`
}

// RegistratorConfig identifies the workload allowed to register clients in an
// environment and the keys that sign its software statements.
type RegistratorConfig struct {
	Subject            string `yaml:"subject"`
	RegistratorJwksUri string `yaml:"registratorJwksUri"`
	SigningAlg         string `yaml:"signingAlg"`
}

type Environments []Environment

func (e Environments) Validate() error {
	if len(e) == 0 {
		return fmt.Errorf("must not be empty")
	}
	names := make(map[Name]struct{}, len(e))
	issuers := make(map[TokenIssuer]struct{}, len(e))
	for i, env := range e {
		if err := env.Name.Validate(); err != nil {
			return fmt.Errorf("environment %d name: %w", i, err)
		}
		if _, ok := names[env.Name]; ok {
			return fmt.Errorf("environment name %q is duplicated", env.Name)
		}
		names[env.Name] = struct{}{}
		if err := validateSecureURL(string(env.ClientAuthIssuer)); err != nil {
			return fmt.Errorf("environment %q client auth issuer: %w", env.Name, err)
		}
		if _, ok := issuers[env.ClientAuthIssuer]; ok {
			return fmt.Errorf("environment %q client auth issuer %q is duplicated", env.Name, env.ClientAuthIssuer)
		}
		issuers[env.ClientAuthIssuer] = struct{}{}
		if env.Registrator.Subject == "" {
			return fmt.Errorf("environment %q registrator subject must not be empty", env.Name)
		}
		if err := validateSecureURL(env.Registrator.RegistratorJwksUri); err != nil {
			return fmt.Errorf("environment %q registrator JWKS URI: %w", env.Name, err)
		}
		if err := jwa.ValidateAlgorithms(env.Registrator.SigningAlg); err != nil {
			return fmt.Errorf("environment %q registrator signing algorithm %q is unsupported: %w", env.Name, env.Registrator.SigningAlg, err)
		}
	}
	return nil
}

// ClientAuthIssuers returns the Kubernetes issuers of all environments.
func (e Environments) ClientAuthIssuers() []TokenIssuer {
	issuers := make([]TokenIssuer, len(e))
	for i, env := range e {
		issuers[i] = env.ClientAuthIssuer
	}
	return issuers
}

func validateSecureURL(value string) error {
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
