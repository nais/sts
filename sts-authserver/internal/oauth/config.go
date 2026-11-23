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
	Issuer            api.STSIssuer     `yaml:"issuer"`
	Environments      Environments      `yaml:"environments"`
	ClientAuthIssuers ClientAuthIssuers `yaml:"clientAuthIssuers"`
	ExternalIssuers   IssuerAliases     `yaml:"externalIssuers"`
	TokenExpiry       time.Duration     `yaml:"tokenExpiry" default:"15m"`
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

type IssuerAliases map[string]jwt.Issuer

func (s IssuerAliases) Issuers() []jwt.Issuer {
	return slices.Collect(maps.Values(s))
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
	if err := c.ClientAuthIssuers.Validate(); err != nil {
		return fmt.Errorf("clientAuthIssuers: %w", err)
	}
	registrators := make(map[struct{ issuer, subject string }]Name)
	for _, env := range c.Environments {
		for _, ref := range env.ClientAuthIssuers {
			if _, ok := c.ClientAuthIssuers[ref]; !ok {
				return fmt.Errorf("environment %q references unknown client auth issuer %q", env.Name, ref)
			}
		}
		ref := env.Registrator.IssuerRef
		cfg, ok := c.ClientAuthIssuers[ref]
		if !ok {
			return fmt.Errorf("environment %q registrator references unknown issuerRef %q", env.Name, ref)
		}
		if cfg.Mode != ClientAuthWorkload {
			return fmt.Errorf("environment %q registrator issuerRef %q must use workload mode", env.Name, ref)
		}
		if !slices.Contains(env.ClientAuthIssuers, ref) {
			return fmt.Errorf("environment %q registrator issuerRef %q must be trusted by the environment", env.Name, ref)
		}
		identity := struct{ issuer, subject string }{string(cfg.Issuer), env.Registrator.Subject}
		if previous, exists := registrators[identity]; exists {
			return fmt.Errorf("registrator issuer %q and subject %q match environments %q and %q", cfg.Issuer, env.Registrator.Subject, previous, env.Name)
		}
		registrators[identity] = env.Name
	}
	for alias, issuer := range c.ExternalIssuers {
		for name, cfg := range c.ClientAuthIssuers {
			if cfg.Alias == alias || cfg.Issuer == issuer {
				return fmt.Errorf("subject token issuer %q overlaps client auth issuer %q", issuer, name)
			}
		}
	}
	if c.TokenExpiry <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}
	return nil
}

// Environment groups registered workload clients and their trusted authentication
// issuers. Its name is part of every client ID and must remain stable.
type Environment struct {
	Name              Name              `yaml:"name"`
	ClientAuthIssuers []string          `yaml:"clientAuthIssuers"`
	Registrator       RegistratorConfig `yaml:"registrator"`
}

type ClientAuthMode string

const (
	ClientAuthWorkload      ClientAuthMode = "workload"
	ClientAuthImpersonation ClientAuthMode = "impersonation"
)

type ClientAuthConfig struct {
	Issuer           jwt.Issuer     `yaml:"issuer"`
	Alias            string         `yaml:"alias"`
	Mode             ClientAuthMode `yaml:"mode"`
	ClientClaims     *ClientClaims  `yaml:"clientClaims"`
	ExpectedAudience string         `yaml:"expectedAudience" default:"nais"`
	// TODO: rename to MaxTokenLifetime
	MaxClientAuthTokenLifetime time.Duration `yaml:"maxClientAuthTokenLifetime" default:"1h"`
}

// ClientClaims contains dotted paths to nonempty string claims.
type ClientClaims struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

func (c ClientAuthConfig) Validate() error {
	if c.Issuer == "" || c.Alias == "" {
		return fmt.Errorf("client auth issuer and alias must not be empty")
	}
	if err := validateSecureURL(string(c.Issuer)); err != nil {
		return fmt.Errorf("client auth issuer: %w", err)
	}
	if c.MaxClientAuthTokenLifetime <= 0 {
		return fmt.Errorf("maximum client auth token lifetime must be positive")
	}
	if c.ExpectedAudience == "" {
		return fmt.Errorf("expected audience must not be empty")
	}

	switch c.Mode {
	case ClientAuthWorkload:
		if c.ClientClaims == nil || c.ClientClaims.Namespace == "" || c.ClientClaims.Name == "" {
			return fmt.Errorf("workload mode requires clientClaims.namespace and clientClaims.name")
		}
	case ClientAuthImpersonation:
		if c.ClientClaims != nil {
			return fmt.Errorf("impersonation mode must not define clientClaims")
		}
	default:
		return fmt.Errorf("client auth mode must be workload or impersonation, got %q", c.Mode)
	}
	return nil
}

// ClientAuthIssuers defines authentication rules once per issuer URL.
type ClientAuthIssuers map[string]ClientAuthConfig

func (c ClientAuthIssuers) Validate() error {
	if len(c) == 0 {
		return fmt.Errorf("at least one issuer is required")
	}
	seen := make(map[jwt.Issuer]string)
	for name, cfg := range c {
		if err := Name(name).Validate(); err != nil {
			return fmt.Errorf("invalid client auth issuer name %q: %w", name, err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("issuer %q: %w", name, err)
		}
		if previous, exists := seen[cfg.Issuer]; exists {
			return fmt.Errorf("duplicate issuer URL %q in %q and %q", cfg.Issuer, previous, name)
		}
		seen[cfg.Issuer] = name
	}
	return nil
}

// ReferencedClientAuthIssuers returns definitions referenced by at least one
// environment. A shared definition alone does not grant trust or require
// issuer discovery.
func (c AuthorizationServerConfig) ReferencedClientAuthIssuers() ClientAuthIssuers {
	issuers := make(ClientAuthIssuers)
	for _, env := range c.Environments {
		for _, ref := range env.ClientAuthIssuers {
			if cfg, ok := c.ClientAuthIssuers[ref]; ok {
				issuers[ref] = cfg
			}
		}
	}
	return issuers
}

// UnmarshalYAML applies defaults to each environment created during decoding.
func (e *Environment) UnmarshalYAML(node *yaml.Node) error {
	// Use a distinct type to avoid calling UnmarshalYAML recursively.
	type plain Environment
	var env plain
	if err := decodeWithDefaults(node, &env); err != nil {
		return err
	}
	*e = Environment(env)
	return nil
}

// UnmarshalYAML applies defaults to each issuer definition; map values are not
// covered by DefaultAuthorizationServerConfig.
func (c *ClientAuthConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain ClientAuthConfig
	var cfg plain
	if err := decodeWithDefaults(node, &cfg); err != nil {
		return err
	}
	*c = ClientAuthConfig(cfg)
	return nil
}

func decodeWithDefaults(node *yaml.Node, target any) error {
	if err := config.Apply(target); err != nil {
		return err
	}

	// Node.Decode does not inherit KnownFields from the outer decoder. Resolve
	// aliases first, including anchors defined in another entry.
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
	return decoder.Decode(target)
}

// RegistratorConfig identifies the workload allowed to register clients in an
// environment and the keys that sign its software statements.
type RegistratorConfig struct {
	IssuerRef          string `yaml:"issuerRef"`
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
		if len(env.ClientAuthIssuers) == 0 {
			return fmt.Errorf("environment %q requires client auth issuer references", env.Name)
		}
		seen := make(map[string]bool)
		for _, ref := range env.ClientAuthIssuers {
			if ref == "" || seen[ref] {
				return fmt.Errorf("environment %q has an empty or duplicate client auth issuer reference %q", env.Name, ref)
			}
			seen[ref] = true
		}
		if env.Registrator.IssuerRef == "" {
			return fmt.Errorf("environment %q registrator issuerRef must not be empty", env.Name)
		}

		names[env.Name] = struct{}{}
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

func (c AuthorizationServerConfig) GetClientAuthConfig(issuer jwt.Issuer) (ClientAuthConfig, bool) {
	for _, cfg := range c.ClientAuthIssuers {
		if cfg.Issuer == issuer {
			return cfg, true
		}
	}
	return ClientAuthConfig{}, false
}

func (c AuthorizationServerConfig) EnvironmentAllowsIssuer(environment Name, issuer jwt.Issuer) bool {
	for _, env := range c.Environments {
		if env.Name != environment {
			continue
		}
		for _, ref := range env.ClientAuthIssuers {
			if cfg, ok := c.ClientAuthIssuers[ref]; ok && cfg.Issuer == issuer {
				return true
			}
		}
		return false
	}
	return false
}

func (c AuthorizationServerConfig) GetIssuerAlias(issuer jwt.Issuer) (string, bool) {
	if cfg, ok := c.GetClientAuthConfig(issuer); ok {
		return cfg.Alias, true
	}
	for name, iss := range c.ExternalIssuers {
		if iss == issuer {
			return name, true
		}
	}
	return "", false
}

func (c ClientAuthConfig) GetNamespaceAndName(claims *jwt.AccessTokenClaims) (namespace, name string, err error) {
	name, err = jwt.StringClaim(claims.Claims, c.ClientClaims.Name)
	if err != nil {
		return "", "", fmt.Errorf("clientClaims.name: %w", err)
	}
	namespace, err = jwt.StringClaim(claims.Claims, c.ClientClaims.Namespace)
	if err != nil {
		return "", "", fmt.Errorf("clientClaims.namespace: %w", err)
	}
	return namespace, name, nil
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
