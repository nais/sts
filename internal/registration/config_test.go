package registration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientRegistratorsValidate(t *testing.T) {
	valid := func() ClientRegistrators {
		return ClientRegistrators{&ClientRegistratorConfig{
			Issuer:                 "https://issuer.example",
			Subject:                "registrator",
			ClientJwksUri:          "https://issuer.example/jwks",
			RequiredAlgs:           []string{"RS256"},
			ManagedWorkloadIssuers: []string{"https://workload.example"},
		}}
	}

	tests := map[string]func(*ClientRegistratorConfig){
		"invalid managed issuer": func(r *ClientRegistratorConfig) { r.ManagedWorkloadIssuers = []string{"http://example.com"} },
		"duplicate managed issuer": func(r *ClientRegistratorConfig) {
			r.ManagedWorkloadIssuers = []string{"https://workload.example", "https://workload.example"}
		},
		"unsupported algorithm": func(r *ClientRegistratorConfig) { r.RequiredAlgs = []string{"EdDSA"} },
		"duplicate algorithm":   func(r *ClientRegistratorConfig) { r.RequiredAlgs = []string{"RS256", "RS256"} },
	}

	require.NoError(t, valid().Validate())
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			registrators := valid()
			mutate(registrators[0])
			require.Error(t, registrators.Validate())
		})
	}
}

func TestClientRegistratorsDefaultManagedWorkloadIssuer(t *testing.T) {
	registrators := ClientRegistrators{&ClientRegistratorConfig{
		Issuer:        "https://issuer.example",
		Subject:       "registrator",
		ClientJwksUri: "https://issuer.example/jwks",
		RequiredAlgs:  []string{"RS256"},
	}}

	require.NoError(t, registrators.Validate())
	require.Equal(t, []string{"https://issuer.example"}, registrators[0].managedWorkloadIssuers())
}
