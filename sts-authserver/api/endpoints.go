package api

import "strings"

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

// OAuthDiscoveryEndpoint returns the OAuth authorization server metadata URL for the issuer.
func (i STSIssuer) OAuthDiscoveryEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + OAuthDiscoveryPath
}
