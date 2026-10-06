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
encryptionKeyFile: unused-key-file
authorizationServer:
  issuer: https://sts.example
  clientAuthIssuers: [https://client.example]
  subjectTokenIssuers: 
   https://subject.example: issuerName
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

func TestEncryptionKey(t *testing.T) {
	t.Run("missing path rejected", func(t *testing.T) {
		_, err := loadFile(writeConfig(t, `databaseUrl: postgres://localhost/sts`+validAuthorizationServer))
		require.ErrorContains(t, err, "encryption key file must not be empty")
	})

	t.Run("reads base64 key with trailing newline", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "key")
		require.NoError(t, os.WriteFile(keyPath, []byte("c2VjcmV0\n"), 0o600))
		cfg := Config{EncryptionKeyFile: keyPath}
		key, err := cfg.ReadEncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, []byte("secret"), key)
	})

	t.Run("missing file returns a path error", func(t *testing.T) {
		_, err := (Config{EncryptionKeyFile: filepath.Join(t.TempDir(), "missing")}).ReadEncryptionKey()
		require.ErrorContains(t, err, "read encryption key file")
	})

	t.Run("invalid base64 does not expose contents", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "key")
		require.NoError(t, os.WriteFile(keyPath, []byte("secret-value!"), 0o600))
		_, err := (Config{EncryptionKeyFile: keyPath}).ReadEncryptionKey()
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret-value")
	})
}

const validAuthorizationServer = `
authorizationServer:
  issuer: https://sts.example
  clientAuthIssuers: [https://client.example]
  subjectTokenIssuers:
    https://subject.example: issuerName
`

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
