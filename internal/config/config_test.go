package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFileUsesDefaults(t *testing.T) {
	cfg, err := loadFile(writeConfig(t, `
databaseUrl: postgres://localhost/sts
authorizationServer:
  issuer: https://sts.example
  clientAuthIssuers: [https://client.example]
  subjectTokenIssuers: [https://subject.example]
`))
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.BindAddress)
	assert.Equal(t, ":8081", cfg.InternalBindAddress)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, "nais", cfg.AuthorizationServerConfig.ExpectedAudience)
	assert.Equal(t, []string{"RS256"}, cfg.AuthorizationServerConfig.ClientAuthSigningAlgorithms)
	assert.Equal(t, time.Hour, cfg.AuthorizationServerConfig.MaxClientAuthTokenLifetime)
	assert.Equal(t, 15*time.Minute, cfg.AuthorizationServerConfig.TokenExpiry)
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	_, err := loadFile(writeConfig(t, "unknown: value\n"))
	require.ErrorContains(t, err, "field unknown not found")
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join("..", "..", "config.example.yaml"))
	_, err := Load()
	require.NoError(t, err)
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
