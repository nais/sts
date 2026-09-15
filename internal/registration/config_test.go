package registration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientRegistratorsValidate(t *testing.T) {
	valid := func() ClientRegistrators {
		return ClientRegistrators{&ClientRegistratorConfig{
			Issuer:        "https://issuer.example",
			Subject:       "registrator",
			ClientJwksUri: "https://issuer.example/jwks",
			RequiredAlgs:  []string{"RS256"},
		}}
	}

	tests := map[string]func(*ClientRegistratorConfig){
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
