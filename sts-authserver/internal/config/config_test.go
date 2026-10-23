package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nais/sts/api"
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
	assert.Equal(t, []oauth.TokenIssuer{"https://client.example"}, cfg.AuthorizationServerConfig.Environments.ClientAuthIssuers())
	assert.Equal(t, oauth.SubjectTokenIssuers{"https://subject.example": "issuerName"}, cfg.AuthorizationServerConfig.SubjectTokenIssuers)
	assert.Equal(t, ":8080", cfg.BindAddress)
	assert.Equal(t, ":8081", cfg.InternalBindAddress)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, "nais", cfg.AuthorizationServerConfig.ExpectedAudience)
	assert.Equal(t, []string{"RS256"}, cfg.AuthorizationServerConfig.ClientAuthSigningAlgorithms)
	assert.Equal(t, time.Hour, cfg.AuthorizationServerConfig.MaxClientAuthTokenLifetime)
	assert.Equal(t, 15*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
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
	_, err := loadFile(writeConfig(t, "unknown: value\n"))
	require.ErrorContains(t, err, "field unknown not found")
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join("..", "..", "config.example.yaml"))
	cfg, err := Load()
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
