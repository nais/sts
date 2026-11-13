package api

type ClientRegistration struct {
	SoftwareStatement string `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	ClientID string `json:"client_id"`
}

type SoftwareStatement struct {
	Client              Client              `json:"client"`
	AuthorizationPolicy AuthorizationPolicy `json:"authorization_policy,omitzero"`
}

type Client struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type AuthorizationPolicy struct {
	AllowAll          bool               `json:"allow_all,omitempty"`
	AllowedNamespaces []string           `json:"allowed_namespaces,omitempty"`
	AllowedScopes     []string           `json:"allowed_scopes,omitempty"`
	Clients           []AuthorizedClient `json:"clients,omitempty"`
}

type AuthorizedClient struct {
	Client
	Roles []string `json:"roles,omitempty"`
}

type DiscoveryMetadata struct {
	// Issuer is the identifier of the OP and is used in the tokens as `iss` claim.
	Issuer string `json:"issuer,omitempty"`

	// TokenEndpoint is the URL of the OAuth 2.0 Token Endpoint where all tokens are issued, except when using Implicit Flow
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// JwksURI is the URL of the JSON Web Key Set. This site contains the signing keys that RPs can use to validate the signature.
	// It may also contain the OP's encryption keys that RPs can use to encrypt request to the OP.
	JwksURI string `json:"jwks_uri,omitempty"`

	// GrantTypesSupported contains a list of the OAuth 2.0 grant_type values that the OP supports. If omitted, the default value is ["authorization_code", "implicit"].
	GrantTypesSupported []GrantType `json:"grant_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported contains a list of Client Authentication methods supported by the Token Endpoint. If omitted, the default is client_secret_basic.
	TokenEndpointAuthMethodsSupported []AuthMethod `json:"token_endpoint_auth_methods_supported,omitempty"`

	// RegistrationEndpoint is the URL for the Dynamic Client Registration.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
}

const (
	// GrantTypeClientCredentials defines the grant_type `client_credentials` used for the Token Request in the Client Credentials Token Flow
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypeTokenExchange defines the grant_type `urn:ietf:params:oauth:grant-type:token-exchange` used for the OAuth Token Exchange Grant
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- Public OAuth grant type identifier, not a credential.
)

type (
	GrantType  string
	AuthMethod string
)

const (
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
)
