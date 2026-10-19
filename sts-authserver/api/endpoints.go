package api

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	// RegistrationPath is the path for client registration requests.
	RegistrationPath = "/v1/registration/client"
	// TokenPath is the path for OAuth token requests.
	TokenPath = "/token"
	// JWKSPath is the path for the public JSON Web Key Set.
	JWKSPath = "/jwks"
	// OAuthDiscoveryPath is the path for OAuth authorization server metadata.
	OAuthDiscoveryPath = "/.well-known/oauth-authorization-server"
)

// STSIssuer identifies this STS authorization server and its endpoints.
type STSIssuer string

// String returns the issuer identifier unchanged.
func (i STSIssuer) String() string {
	return string(i)
}

func (i STSIssuer) validate() error {
	if i == "" {
		return fmt.Errorf("issuer is empty")
	}
	u, err := url.Parse(i.String())
	if err != nil {
		return fmt.Errorf("issuer is not a valid URL: %w", err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("issuer URL does not contain a scheme")
	}
	return nil
}

// TokenEndpoint returns the STS token endpoint URL for the issuer.
func (i STSIssuer) TokenEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + TokenPath
}

// JWKSEndpoint returns the STS public JSON Web Key Set URL for the issuer.
func (i STSIssuer) JWKSEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + JWKSPath
}

// RegistrationEndpoint returns the STS client registration endpoint URL for the issuer.
func (i STSIssuer) RegistrationEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + RegistrationPath
}

// DeleteEndpoint returns the STS client deletion endpoint URL for the issuer and given client ID.
func (i STSIssuer) DeleteEndpoint(clientID string) string {
	return strings.TrimSuffix(string(i), "/") + RegistrationPath + "/" + url.PathEscape(clientID)
}

// OAuthDiscoveryEndpoint returns the OAuth authorization server metadata URL for the issuer.
func (i STSIssuer) OAuthDiscoveryEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + OAuthDiscoveryPath
}
