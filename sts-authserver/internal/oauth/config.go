package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/nais/sts/api"
)

type AuthorizationServerConfig struct {
	Issuer                      api.STSIssuer       `yaml:"issuer"`
	ExpectedAudience            string              `yaml:"expectedAudience"`
	ClientAuthIssuers           []TokenIssuer       `yaml:"clientAuthIssuers"`
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
	if err := ValidateSecureURL(string(c.Issuer)); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if len(c.ClientAuthIssuers) == 0 {
		return fmt.Errorf("client auth issuers must not be empty")
	}
	if err := ValidateSigningAlgorithms(c.ClientAuthSigningAlgorithms); err != nil {
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

var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
}

func ValidateSigningAlgorithms(algorithms []string) error {
	if len(algorithms) == 0 {
		return fmt.Errorf("must not be empty")
	}
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if _, ok := supportedSigningAlgorithms[algorithm]; !ok {
			return fmt.Errorf("unsupported signing algorithm %q", algorithm)
		}
		if _, ok := seen[algorithm]; ok {
			return fmt.Errorf("duplicate signing algorithm %q", algorithm)
		}
		seen[algorithm] = struct{}{}
	}
	return nil
}

func isSupportedSigningAlgorithm(algorithm string) bool {
	_, ok := supportedSigningAlgorithms[algorithm]
	return ok
}

func ValidateSecureURL(value string) error {
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
