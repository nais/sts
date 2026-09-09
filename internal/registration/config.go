package registration

type ClientRegistratorConfig struct {
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	ClientJwksUri string   `json:"client_jwks_uri"`
	RequiredAlgs  []string `json:"required_algs"`
}

type ClientRegistrators = []*ClientRegistratorConfig
