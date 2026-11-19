package oauth

import (
	"testing"
	"time"

	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestDefaultAuthorizationServerConfig(t *testing.T) {
	cfg := DefaultAuthorizationServerConfig()
	assert.Equal(t, "nais", cfg.ExpectedAudience)
	assert.Equal(t, time.Hour, cfg.MaxClientAuthTokenLifetime)
	assert.Equal(t, 15*time.Minute, cfg.TokenExpiry)

	cfg.ExpectedAudience = "custom"
	assert.Equal(t, "nais", DefaultAuthorizationServerConfig().ExpectedAudience)
}

func TestAuthorizationServerConfigValidateExternalIssuers(t *testing.T) {
	for name, test := range map[string]struct {
		issuers IssuerAliases
		wantErr bool
	}{
		"none":               {},
		"alias nais":         {issuers: IssuerAliases{"nais": "https://subject.example"}},
		"environment alias":  {issuers: IssuerAliases{"kubernetes": "https://subject.example"}, wantErr: true},
		"environment issuer": {issuers: IssuerAliases{"subject": "https://client.example"}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultAuthorizationServerConfig()
			cfg.Issuer = "https://sts.example"
			cfg.Environments = validEnvironments()
			cfg.ExternalIssuers = test.issuers

			if test.wantErr {
				require.Error(t, cfg.Validate())
			} else {
				require.NoError(t, cfg.Validate())
			}
		})
	}
}

func TestGetIssuerAlias(t *testing.T) {
	cfg := DefaultAuthorizationServerConfig()
	cfg.Environments = validEnvironments()
	cfg.Environments[0].ClientAuthIssuerAlias = "cluster"
	cfg.ExternalIssuers = IssuerAliases{"identity": "https://subject.example"}

	for _, tt := range []struct {
		issuer jwt.Issuer
		alias  string
		found  bool
	}{
		{"https://client.example", "cluster", true},
		{"https://subject.example", "identity", true},
		{"https://unknown.example", "", false},
	} {
		t.Run(string(tt.issuer), func(t *testing.T) {
			alias, ok := cfg.GetIssuerAlias(tt.issuer)
			assert.Equal(t, tt.alias, alias)
			assert.Equal(t, tt.found, ok)
		})
	}
}

func TestEnvironmentYAMLDefaults(t *testing.T) {
	for _, tt := range []struct {
		name  string
		yaml  string
		alias string
	}{
		{"omitted", "name: dev", "kubernetes"},
		{"override", "name: dev\nclientAuthIssuerAlias: cluster", "cluster"},
		{"explicit empty", "name: dev\nclientAuthIssuerAlias: ''", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var env Environment
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), &env))
			assert.Equal(t, tt.alias, env.ClientAuthIssuerAlias)
		})
	}
}

func TestEnvironmentYAMLAnchors(t *testing.T) {
	var envs Environments
	require.NoError(t, yaml.Unmarshal([]byte(`
- name: dev
  registrator: &registrator
    subject: operator
    registratorJwksUri: https://operator.example/jwks
    signingAlg: ES256
- name: prod
  registrator: *registrator
`), &envs))
	require.Len(t, envs, 2)
	assert.Equal(t, envs[0].Registrator, envs[1].Registrator)
	assert.Equal(t, "kubernetes", envs[1].ClientAuthIssuerAlias)
}

func TestEnvironmentsAllowSharedIssuer(t *testing.T) {
	envs := validEnvironments()
	other := envs[0]
	other.Name = "other"
	require.NoError(t, append(envs, other).Validate())
}

func validEnvironments() Environments {
	return Environments{{
		Name:                  "dev",
		ClientAuthConfig:      "https://client.example",
		ClientAuthIssuerAlias: "kubernetes",
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
		"insecure issuer": func(e Environments) Environments { e[0].ClientAuthConfig = "http://client.example"; return e },
		"missing issuer":  func(e Environments) Environments { e[0].ClientAuthConfig = ""; return e },
		"missing alias":   func(e Environments) Environments { e[0].ClientAuthIssuerAlias = ""; return e },
		"missing subject": func(e Environments) Environments { e[0].Registrator.Subject = ""; return e },
		"insecure JWKS URI": func(e Environments) Environments {
			e[0].Registrator.RegistratorJwksUri = "http://registrator.example"
			return e
		},
		"unsupported alg": func(e Environments) Environments { e[0].Registrator.SigningAlg = "EdDSA"; return e },
		"duplicate name": func(e Environments) Environments {
			other := e[0]
			other.ClientAuthConfig = "https://other.example"
			return append(e, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, mutate(validEnvironments()).Validate())
		})
	}
}
