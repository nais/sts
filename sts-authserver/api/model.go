package api

type ClientRegistration struct {
	SoftwareStatement string `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	ClientID string `json:"client_id"`
}

type SoftwareStatement struct {
	ClientID              string                `json:"client_id"`
	Workload              Workload              `json:"workload"`
	AuthorizationPolicies []AuthorizationPolicy `json:"authorization_policies"`
}

type Workload struct {
	Environment string `json:"environment"`
	Issuer      string `json:"issuer"`
	Namespace   string `json:"namespace"`
	Name        string `json:"workload"`
}

type AuthorizationPolicy struct {
	Consumer string   `json:"consumer"`
	Roles    []string `json:"roles"`
}
