package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationServerConfigRejectsInvalidClientAuthSigningAlgorithms(t *testing.T) {
	for name, algorithms := range map[string][]string{
		"duplicate":   {"RS256", "RS256"},
		"unsupported": {"EdDSA"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := AuthorizationServerConfig{
				Issuer:                      "https://sts.example",
				ExpectedAudience:            "nais",
				Environments:                validEnvironments(),
				ClientAuthSigningAlgorithms: algorithms,
				SubjectTokenIssuers:         map[TokenIssuer]string{"https://subject.example": "issuerName"},
				MaxClientAuthTokenLifetime:  time.Hour,
				TokenExpiry:                 time.Hour,
			}

			require.Error(t, cfg.Validate())
		})
	}
}

func TestAuthorizationServerConfigAllowsNoSubjectTokenIssuers(t *testing.T) {
	cfg := AuthorizationServerConfig{
		Issuer:                      "https://sts.example",
		ExpectedAudience:            "nais",
		Environments:                validEnvironments(),
		ClientAuthSigningAlgorithms: []string{"RS256"},
		MaxClientAuthTokenLifetime:  time.Hour,
		TokenExpiry:                 time.Hour,
	}

	require.NoError(t, cfg.Validate())
}

func TestAsymmetricAlgorithms(t *testing.T) {
	assert.Equal(t,
		[]string{"ES256", "RS256", "PS512"},
		asymmetricAlgorithms([]string{"ES256", "none", "RS999", "EdDSA", "RS256", "PS512"}),
	)
}

func validEnvironments() Environments {
	return Environments{{
		Name:             "dev",
		ClientAuthIssuer: "https://client.example",
		Registrator: RegistratorConfig{
			Subject:            "registrator",
			RegistratorJwksUri: "https://registrator.example/jwks",
			SigningAlg:         "RS256",
		},
	}}
}

func TestEnvironmentsValidate(t *testing.T) {
	require.NoError(t, validEnvironments().Validate())

	for name, mutate := range map[string]func(Environments) Environments{
		"empty":           func(Environments) Environments { return nil },
		"invalid name":    func(e Environments) Environments { e[0].Name = "Dev"; return e },
		"insecure issuer": func(e Environments) Environments { e[0].ClientAuthIssuer = "http://client.example"; return e },
		"missing subject": func(e Environments) Environments { e[0].Registrator.Subject = ""; return e },
		"insecure JWKS URI": func(e Environments) Environments {
			e[0].Registrator.RegistratorJwksUri = "http://registrator.example"
			return e
		},
		"unsupported alg": func(e Environments) Environments { e[0].Registrator.SigningAlg = "EdDSA"; return e },
		"duplicate name": func(e Environments) Environments {
			other := e[0]
			other.ClientAuthIssuer = "https://other.example"
			return append(e, other)
		},
		"duplicate issuer": func(e Environments) Environments { other := e[0]; other.Name = "other"; return append(e, other) },
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, mutate(validEnvironments()).Validate())
		})
	}
}
