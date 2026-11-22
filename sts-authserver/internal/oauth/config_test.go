package oauth

import (
	"testing"
	"time"

	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func validAuthorizationServerConfig() AuthorizationServerConfig {
	cfg := DefaultAuthorizationServerConfig()
	cfg.Issuer = "https://sts.example"
	cfg.ClientAuthIssuers = ClientAuthIssuers{
		"cluster-dev": {
			Issuer: "https://client.example", Alias: "kubernetes", Mode: ClientAuthWorkload,
			ClientClaims: &ClientClaims{Namespace: "kubernetes.io.namespace", Name: "kubernetes.io.serviceaccount.name"},
		},
		"employee": {Issuer: "https://people.example", Alias: "employee", Mode: ClientAuthImpersonation},
	}
	cfg.Environments = Environments{{
		Name: "dev", ClientAuthIssuers: []string{"cluster-dev", "employee"},
		Registrator: RegistratorConfig{
			IssuerRef: "cluster-dev", Subject: "registrator",
			RegistratorJwksUri: "https://registrator.example/jwks", SigningAlg: "RS256",
		},
	}}
	return cfg
}

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
		"client auth alias":  {issuers: IssuerAliases{"kubernetes": "https://subject.example"}, wantErr: true},
		"client auth issuer": {issuers: IssuerAliases{"subject": "https://client.example"}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAuthorizationServerConfig()
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
	cfg := validAuthorizationServerConfig()
	cfg.ExternalIssuers = IssuerAliases{"identity": "https://subject.example"}
	for _, tt := range []struct {
		issuer jwt.Issuer
		alias  string
		found  bool
	}{
		{"https://client.example", "kubernetes", true},
		{"https://people.example", "employee", true},
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

func TestSharedIssuerYAML(t *testing.T) {
	cfg := DefaultAuthorizationServerConfig()
	require.NoError(t, yaml.Unmarshal([]byte(`
issuer: https://sts.example
clientAuthIssuers:
  cluster-dev:
    issuer: https://client.example
    alias: kubernetes
    mode: workload
    clientClaims:
      namespace: kubernetes.io.namespace
      name: kubernetes.io.serviceaccount.name
  employee:
    issuer: https://people.example
    alias: employee
    mode: impersonation
environments:
  - name: dev
    clientAuthIssuers: &issuers [cluster-dev, employee]
    registrator: &registrator
      issuerRef: cluster-dev
      subject: operator-dev
      registratorJwksUri: https://operator.example/jwks
      signingAlg: ES256
  - name: prod
    clientAuthIssuers: *issuers
    registrator:
      <<: *registrator
      subject: operator-prod
`), &cfg))
	cfg.ClientAuthIssuers["unused"] = ClientAuthConfig{Issuer: "https://unused.example", Alias: "unused", Mode: ClientAuthImpersonation}
	require.NoError(t, cfg.Validate())
	require.Len(t, cfg.Environments, 2)
	assert.Equal(t, cfg.Environments[0].ClientAuthIssuers, cfg.Environments[1].ClientAuthIssuers)
	assert.Equal(t, []jwt.Issuer{"https://client.example", "https://people.example"}, cfg.ClientAuthIssuerURLs())
	for _, env := range cfg.Environments {
		assert.True(t, cfg.EnvironmentAllowsIssuer(env.Name, "https://people.example"))
	}
}

func TestClientAuthConfigValidate(t *testing.T) {
	for name, mutate := range map[string]func(*ClientAuthConfig){
		"missing mode":        func(c *ClientAuthConfig) { c.Mode = "" },
		"unknown mode":        func(c *ClientAuthConfig) { c.Mode = "unknown" },
		"missing issuer":      func(c *ClientAuthConfig) { c.Issuer = "" },
		"insecure issuer":     func(c *ClientAuthConfig) { c.Issuer = "http://client.example" },
		"missing alias":       func(c *ClientAuthConfig) { c.Alias = "" },
		"missing mappings":    func(c *ClientAuthConfig) { c.ClientClaims = nil },
		"missing namespace":   func(c *ClientAuthConfig) { c.ClientClaims.Namespace = "" },
		"missing name":        func(c *ClientAuthConfig) { c.ClientClaims.Name = "" },
		"irrelevant mappings": func(c *ClientAuthConfig) { c.Mode = ClientAuthImpersonation },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAuthorizationServerConfig().ClientAuthIssuers["cluster-dev"]
			mutate(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
	require.NoError(t, (ClientAuthConfig{Issuer: "https://people.example", Alias: "employee", Mode: ClientAuthImpersonation}).Validate())
}

func TestAuthorizationServerConfigReferences(t *testing.T) {
	require.NoError(t, validAuthorizationServerConfig().Validate())
	for name, mutate := range map[string]func(*AuthorizationServerConfig){
		"no definitions": func(c *AuthorizationServerConfig) { c.ClientAuthIssuers = nil },
		"duplicate URL": func(c *AuthorizationServerConfig) {
			c.ClientAuthIssuers["duplicate"] = c.ClientAuthIssuers["cluster-dev"]
		},
		"invalid definition name":        func(c *AuthorizationServerConfig) { c.ClientAuthIssuers[""] = c.ClientAuthIssuers["cluster-dev"] },
		"unknown reference":              func(c *AuthorizationServerConfig) { c.Environments[0].ClientAuthIssuers = []string{"unknown"} },
		"unknown registrator issuer":     func(c *AuthorizationServerConfig) { c.Environments[0].Registrator.IssuerRef = "unknown" },
		"person registrator":             func(c *AuthorizationServerConfig) { c.Environments[0].Registrator.IssuerRef = "employee" },
		"registrator issuer not trusted": func(c *AuthorizationServerConfig) { c.Environments[0].ClientAuthIssuers = []string{"employee"} },
		"duplicate registrator identity": func(c *AuthorizationServerConfig) {
			other := c.Environments[0]
			other.Name = "other"
			c.Environments = append(c.Environments, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAuthorizationServerConfig()
			mutate(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestEnvironmentsValidate(t *testing.T) {
	for name, mutate := range map[string]func(Environments) Environments{
		"empty":           func(Environments) Environments { return nil },
		"invalid name":    func(e Environments) Environments { e[0].Name = "Dev"; return e },
		"no issuers":      func(e Environments) Environments { e[0].ClientAuthIssuers = nil; return e },
		"empty reference": func(e Environments) Environments { e[0].ClientAuthIssuers = []string{""}; return e },
		"duplicate reference": func(e Environments) Environments {
			e[0].ClientAuthIssuers = append(e[0].ClientAuthIssuers, e[0].ClientAuthIssuers[0])
			return e
		},
		"missing registrator issuer": func(e Environments) Environments { e[0].Registrator.IssuerRef = ""; return e },
		"missing subject":            func(e Environments) Environments { e[0].Registrator.Subject = ""; return e },
		"insecure JWKS URI": func(e Environments) Environments {
			e[0].Registrator.RegistratorJwksUri = "http://registrator.example"
			return e
		},
		"unsupported alg": func(e Environments) Environments { e[0].Registrator.SigningAlg = "EdDSA"; return e },
		"duplicate name":  func(e Environments) Environments { return append(e, e[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, mutate(validAuthorizationServerConfig().Environments).Validate())
		})
	}
}
