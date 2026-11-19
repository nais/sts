package oauth

import (
	"bytes"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/jwa"
	"github.com/nais/sts/internal/jwt"
	"go.yaml.in/yaml/v3"
)

type AuthorizationServerConfig struct {
	Issuer                     api.STSIssuer `yaml:"issuer"`
	ExpectedAudience           string        `yaml:"expectedAudience" default:"nais"`
	Environments               Environments  `yaml:"environments"`
	ExternalIssuers            IssuerAliases `yaml:"externalIssuers"`
	MaxClientAuthTokenLifetime time.Duration `yaml:"maxClientAuthTokenLifetime" default:"1h"`
	TokenExpiry                time.Duration `yaml:"tokenExpiry" default:"15m"`
}

// DefaultAuthorizationServerConfig returns a fresh configuration initialized from
// default tags. Required fields must still be supplied before validation.
// It panics if a default tag is invalid, which is a programming error.
func DefaultAuthorizationServerConfig() AuthorizationServerConfig {
	var cfg AuthorizationServerConfig
	if err := config.Apply(&cfg); err != nil {
		panic(fmt.Errorf("apply authorization server defaults: %w", err))
	}
	return cfg
}

type IssuerAliases map[jwt.Issuer]string

func (s IssuerAliases) Issuers() []jwt.Issuer {
	return slices.Collect(maps.Keys(s))
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
	for issuer, name := range c.ExternalIssuers {
		for _, env := range c.Environments {
			if env.ClientAuthIssuerAlias == name {
				return fmt.Errorf("subject token issuer %q: alias %q is already used by environment %q", issuer, name, env.Name)
			}
			if env.ClientAuthIssuer == issuer {
				return fmt.Errorf("subject token issuer %q: issuer %q is already used by environment %q", issuer, issuer, env.Name)
			}
		}
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
	Name                  Name              `yaml:"name"`
	ClientAuthIssuer      jwt.Issuer        `yaml:"clientAuthIssuer"`
	ClientAuthIssuerAlias string            `yaml:"clientAuthIssuerAlias" default:"kubernetes"`
	Registrator           RegistratorConfig `yaml:"registrator"`
}

// UnmarshalYAML applies defaults to each environment created during decoding.
func (e *Environment) UnmarshalYAML(node *yaml.Node) error {
	// Use a distinct type to avoid calling UnmarshalYAML recursively.
	type plain Environment
	var env plain
	if err := config.Apply(&env); err != nil {
		return err
	}

	// Node.Decode does not inherit KnownFields from the outer decoder. Resolve
	// aliases first, including anchors defined in another environment entry.
	var values any
	if err := node.Decode(&values); err != nil {
		return err
	}
	data, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&env); err != nil {
		return err
	}
	*e = Environment(env)
	return nil
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
	for i, env := range e {
		if err := env.Name.Validate(); err != nil {
			return fmt.Errorf("environment %d name: %w", i, err)
		}
		if _, ok := names[env.Name]; ok {
			return fmt.Errorf("environment name %q is duplicated", env.Name)
		}
		if env.ClientAuthIssuer == "" || env.ClientAuthIssuerAlias == "" {
			return fmt.Errorf("environment %q client auth issuer and alias must not be empty", env.Name)
		}

		names[env.Name] = struct{}{}
		if err := validateSecureURL(string(env.ClientAuthIssuer)); err != nil {
			return fmt.Errorf("environment %q client auth issuer: %w", env.Name, err)
		}
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

func (c AuthorizationServerConfig) GetIssuerAlias(issuer jwt.Issuer) (string, bool) {
	names := make(map[jwt.Issuer]string, len(c.ExternalIssuers)+len(c.Environments))
	maps.Copy(names, c.ExternalIssuers)
	for _, env := range c.Environments {
		names[env.ClientAuthIssuer] = env.ClientAuthIssuerAlias
	}
	alias, ok := names[issuer]
	return alias, ok
}

// ClientAuthIssuers returns the Kubernetes issuers of all environments.
func (e Environments) ClientAuthIssuers() []jwt.Issuer {
	issuers := make([]jwt.Issuer, len(e))
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
