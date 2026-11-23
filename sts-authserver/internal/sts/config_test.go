package sts

import (
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFileUsesDefaults(t *testing.T) {
	cfg, err := loadFile(writeConfig(t, testConfig+"  externalIssuers:\n    issuerName: https://subject.example\n"))
	require.NoError(t, err)

	assert.Equal(t, api.STSIssuer("https://sts.example"), cfg.AuthorizationServerConfig.Issuer)
	assert.Equal(t, []string{"cluster-dev"}, slices.Collect(maps.Keys(cfg.AuthorizationServerConfig.ReferencedClientAuthIssuers())))
	assert.Equal(t, "kubernetes", cfg.AuthorizationServerConfig.ClientAuthIssuers["cluster-dev"].Alias)
	assert.Equal(t, oauth.IssuerAliases{"issuerName": "https://subject.example"}, cfg.AuthorizationServerConfig.ExternalIssuers)
	assert.Equal(t, ":8080", cfg.BindAddress)
	assert.Equal(t, ":8081", cfg.InternalBindAddress)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, "nais", cfg.AuthorizationServerConfig.ClientAuthIssuers["cluster-dev"].ExpectedAudience)
	assert.Equal(t, time.Hour, cfg.AuthorizationServerConfig.ClientAuthIssuers["cluster-dev"].MaxClientAuthTokenLifetime)
	assert.Equal(t, 15*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
}

const testConfig = `databaseUrl: postgres://localhost/sts
authorizationServer:
  issuer: https://sts.example
  clientAuthIssuers:
    cluster-dev:
      issuer: https://client.example
      alias: kubernetes
      mode: workload
      clientClaims:
        namespace: kubernetes.io.namespace
        name: kubernetes.io.serviceaccount.name
  environments:
    - name: dev
      clientAuthIssuers: [cluster-dev]
      registrator:
        issuerRef: cluster-dev
        subject: registrator
        registratorJwksUri: https://registrator.example/jwks
        signingAlg: RS256
`

func TestLoadFileOverridesDefaults(t *testing.T) {
	base := testConfig

	t.Run("explicit values", func(t *testing.T) {
		cfg, err := loadFile(writeConfig(t, strings.Replace(base, "      mode: workload\n", "      mode: workload\n      expectedAudience: custom\n      maxClientAuthTokenLifetime: 30m\n", 1)+"  tokenExpiry: 5m\n"))
		require.NoError(t, err)
		issuer := cfg.AuthorizationServerConfig.ClientAuthIssuers["cluster-dev"]
		assert.Equal(t, "custom", issuer.ExpectedAudience)
		assert.Equal(t, 30*time.Minute, issuer.MaxClientAuthTokenLifetime)
		assert.Equal(t, 5*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
	})

	for _, tt := range []struct {
		field string
		want  string
	}{
		{`      expectedAudience: ""`, "expected audience must not be empty"},
		{"      maxClientAuthTokenLifetime: 0s", "maximum client auth token lifetime must be positive"},
	} {
		t.Run(strings.TrimSpace(tt.field), func(t *testing.T) {
			_, err := loadFile(writeConfig(t, strings.Replace(base, "      mode: workload\n", "      mode: workload\n"+tt.field+"\n", 1)))
			require.ErrorContains(t, err, tt.want)
		})
	}
	t.Run("tokenExpiry: 0s", func(t *testing.T) {
		_, err := loadFile(writeConfig(t, base+"  tokenExpiry: 0s\n"))
		require.ErrorContains(t, err, "token expiry must be positive")
	})
}

func TestLoadFileDatabaseURL(t *testing.T) {
	for _, tt := range []struct {
		name    string
		fileURL string
		envURL  string
		want    string
		wantErr bool
	}{
		{name: "file only", fileURL: "postgres://file/app", want: "postgres://file/app"},
		{name: "environment overrides file", fileURL: "postgres://file/app", envURL: "postgres://secret/app", want: "postgres://secret/app"},
		{name: "environment only", envURL: "postgres://secret/app", want: "postgres://secret/app"},
		{name: "missing URL", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", tt.envURL)
			cfg, err := loadFile(writeConfig(t, strings.Replace(testConfig, "postgres://localhost/sts", tt.fileURL, 1)))
			if tt.wantErr {
				require.ErrorContains(t, err, "database URL must not be empty")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.DatabaseURL)
		})
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	for _, contents := range []string{
		"unknown: value\n",
		"authorizationServer:\n  unknown: value\n",
		"authorizationServer:\n  environments:\n    - unknown: value\n",
		"authorizationServer:\n  environments:\n    - registrator:\n        unknown: value\n",
		"authorizationServer:\n  clientAuthIssuers:\n    cluster-dev:\n      unknown: value\n",
		"authorizationServer:\n  clientAuthIssuers:\n    cluster-dev:\n      clientClaims:\n        unknown: value\n",
	} {
		_, err := loadFile(writeConfig(t, contents))
		require.ErrorContains(t, err, "field unknown not found")
	}
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join("..", "..", "config.example.yaml"))
	cfg, err := LoadConfig()
	require.NoError(t, err)
	for _, env := range cfg.AuthorizationServerConfig.Environments {
		assert.Equal(t, string(api.SoftwareStatementSigningAlgorithm), env.Registrator.SigningAlg)
	}
}

func TestLoadRenderedConfigs(t *testing.T) {
	dir := os.Getenv("STS_TEST_CONFIG_DIR")
	if dir == "" {
		t.Skip("run mise run check:helm-render to validate rendered chart configuration")
	}
	// The Deployment supplies the database URL through a Secret-backed variable.
	t.Setenv("DATABASE_URL", "postgres://localhost/sts")
	for _, name := range []string{"default.json", "custom.json"} {
		t.Run(name, func(t *testing.T) {
			_, err := loadFile(filepath.Join(dir, name))
			require.NoError(t, err)
		})
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoadFileAdditionalCAFile(t *testing.T) {
	base := testConfig

	cfg, err := loadFile(writeConfig(t, base))
	require.NoError(t, err)
	assert.Empty(t, cfg.AdditionalCAFile)

	cfg, err = loadFile(writeConfig(t, base+"additionalCAFile: /etc/ssl/k3d-ca.pem\n"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/ssl/k3d-ca.pem", cfg.AdditionalCAFile)
}
