package sts

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwt"
	"github.com/nais/sts/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFileUsesDefaults(t *testing.T) {
	cfg, err := loadFile(writeConfig(t, `
databaseUrl: postgres://localhost/sts
authorizationServer:
  issuer: https://sts.example
  environments:
    - name: dev
      clientAuthIssuer: https://client.example
      registrator:
        subject: registrator
        registratorJwksUri: https://registrator.example/jwks
        signingAlg: RS256
  subjectTokenIssuers: 
   https://subject.example: issuerName
`))
	require.NoError(t, err)

	assert.Equal(t, api.STSIssuer("https://sts.example"), cfg.AuthorizationServerConfig.Issuer)
	assert.Equal(t, []jwt.Issuer{"https://client.example"}, cfg.AuthorizationServerConfig.Environments.ClientAuthIssuers())
	assert.Equal(t, oauth.SubjectTokenIssuers{"https://subject.example": "issuerName"}, cfg.AuthorizationServerConfig.SubjectTokenIssuers)
	assert.Equal(t, ":8080", cfg.BindAddress)
	assert.Equal(t, ":8081", cfg.InternalBindAddress)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, "nais", cfg.AuthorizationServerConfig.ExpectedAudience)
	assert.Equal(t, time.Hour, cfg.AuthorizationServerConfig.MaxClientAuthTokenLifetime)
	assert.Equal(t, 15*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	base := "databaseUrl: postgres://localhost/sts\nauthorizationServer:\n  issuer: https://sts.example\n  environments:\n    - name: dev\n      clientAuthIssuer: https://client.example\n      registrator:\n        subject: registrator\n        registratorJwksUri: https://registrator.example/jwks\n        signingAlg: RS256\n"

	t.Run("explicit values", func(t *testing.T) {
		cfg, err := loadFile(writeConfig(t, base+"  expectedAudience: custom\n  maxClientAuthTokenLifetime: 30m\n  tokenExpiry: 5m\n"))
		require.NoError(t, err)
		assert.Equal(t, "custom", cfg.AuthorizationServerConfig.ExpectedAudience)
		assert.Equal(t, 30*time.Minute, cfg.AuthorizationServerConfig.MaxClientAuthTokenLifetime)
		assert.Equal(t, 5*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
	})

	for _, tt := range []struct {
		field string
		want  string
	}{
		{`expectedAudience: ""`, "expected audience must not be empty"},
		{"maxClientAuthTokenLifetime: 0s", "maximum client auth token lifetime must be positive"},
		{"tokenExpiry: 0s", "token expiry must be positive"},
	} {
		t.Run(tt.field, func(t *testing.T) {
			_, err := loadFile(writeConfig(t, base+"  "+tt.field+"\n"))
			require.ErrorContains(t, err, tt.want)
		})
	}
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
			cfg, err := loadFile(writeConfig(t, "databaseUrl: "+tt.fileURL+"\nauthorizationServer:\n  issuer: https://sts.example\n  environments:\n    - name: dev\n      clientAuthIssuer: https://client.example\n      registrator:\n        subject: registrator\n        registratorJwksUri: https://registrator.example/jwks\n        signingAlg: RS256\n"))
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
	base := "databaseUrl: postgres://localhost/sts\nauthorizationServer:\n  issuer: https://sts.example\n  environments:\n    - name: dev\n      clientAuthIssuer: https://client.example\n      registrator:\n        subject: registrator\n        registratorJwksUri: https://registrator.example/jwks\n        signingAlg: RS256\n"

	cfg, err := loadFile(writeConfig(t, base))
	require.NoError(t, err)
	assert.Empty(t, cfg.AdditionalCAFile)

	cfg, err = loadFile(writeConfig(t, base+"additionalCAFile: /etc/ssl/k3d-ca.pem\n"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/ssl/k3d-ca.pem", cfg.AdditionalCAFile)
}
