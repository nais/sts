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

func (i STSIssuer) String() string {
	return string(i)
}

func (i STSIssuer) TokenEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + TokenPath
}

func (i STSIssuer) JWKSEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + JWKSPath
}

func (i STSIssuer) RegistrationEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + RegistrationPath
}

func (i STSIssuer) OAuthDiscoveryEndpoint() string {
	return strings.TrimSuffix(string(i), "/") + OAuthDiscoveryPath
}
