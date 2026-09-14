package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type AuthorizationServerConfig struct {
	Issuer                      Issuer        `yaml:"issuer"`
	ExpectedAudience            string        `yaml:"expectedAudience"`
	ClientAuthIssuers           []Issuer      `yaml:"clientAuthIssuers"`
	ClientAuthSigningAlgorithms []string      `yaml:"clientAuthSigningAlgorithms"`
	SubjectTokenIssuers         []Issuer      `yaml:"subjectTokenIssuers"`
	MaxClientAuthTokenLifetime  time.Duration `yaml:"maxClientAuthTokenLifetime"`
	TokenExpiry                 time.Duration `yaml:"tokenExpiry"`
}

func (c AuthorizationServerConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer must not be empty")
	}
	issuer, err := url.Parse(string(c.Issuer))
	if err != nil || !issuer.IsAbs() || issuer.Host == "" {
		return fmt.Errorf("issuer must be an absolute URL")
	}
	isLoopback := func(host string) bool {
		return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
	}
	if issuer.Scheme != "https" && (issuer.Scheme != "http" || !isLoopback(issuer.Hostname())) {
		return fmt.Errorf("issuer must use https, except for localhost or loopback http URLs")
	}
	if len(c.ClientAuthIssuers) == 0 {
		return fmt.Errorf("client auth issuers must not be empty")
	}
	if err := validateClientAuthSigningAlgorithms(c.ClientAuthSigningAlgorithms); err != nil {
		return err
	}
	if len(c.SubjectTokenIssuers) == 0 {
		return fmt.Errorf("subject token issuers must not be empty")
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

var supportedClientAuthSigningAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
}

func validateClientAuthSigningAlgorithms(algorithms []string) error {
	if len(algorithms) == 0 {
		return fmt.Errorf("client auth signing algorithms must not be empty")
	}
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if _, ok := supportedClientAuthSigningAlgorithms[algorithm]; !ok {
			return fmt.Errorf("unsupported client auth signing algorithm %q", algorithm)
		}
		if _, ok := seen[algorithm]; ok {
			return fmt.Errorf("duplicate client auth signing algorithm %q", algorithm)
		}
		seen[algorithm] = struct{}{}
	}
	return nil
}
