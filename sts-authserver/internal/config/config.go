package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/nais/sts/internal/ioconvenience"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"go.yaml.in/yaml/v3"
)

type Config struct {
	BindAddress               string                          `yaml:"bindAddress"`
	DatabaseURL               string                          `yaml:"databaseUrl"`
	InternalBindAddress       string                          `yaml:"internalBindAddress"`
	LogLevel                  slog.Level                      `yaml:"logLevel"`
	LogFormat                 string                          `yaml:"logFormat"`
	AuthorizationServerConfig oauth.AuthorizationServerConfig `yaml:"authorizationServer"`
	Registrators              registration.ClientRegistrators `yaml:"registrators"`
}

func Load() (Config, error) {
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "config.yaml"
	}
	return loadFile(path)
}

func loadFile(path string) (Config, error) {
	// #nosec G304,G703 -- CONFIG_FILE is an operator-controlled bootstrap path, not request input.
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config file: %w", err)
	}
	defer ioconvenience.CloseWithLog(file, slog.Default())

	cfg := defaultConfig()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("decode config file: multiple YAML documents are not supported")
		}
		return Config{}, fmt.Errorf("decode config file: %w", err)
	}
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		cfg.DatabaseURL = databaseURL
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		BindAddress:         ":8080",
		InternalBindAddress: ":8081",
		LogLevel:            slog.LevelInfo,
		LogFormat:           "text",
		AuthorizationServerConfig: oauth.AuthorizationServerConfig{
			ExpectedAudience:            "nais",
			ClientAuthSigningAlgorithms: []string{"RS256"},
			MaxClientAuthTokenLifetime:  time.Hour,
			TokenExpiry:                 15 * time.Minute,
		},
	}
}

func (c Config) validate() error {
	if c.BindAddress == "" || c.InternalBindAddress == "" {
		return fmt.Errorf("bind addresses must not be empty")
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("database URL must not be empty")
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("log format must be text or json")
	}
	if err := c.AuthorizationServerConfig.Validate(); err != nil {
		return err
	}
	return c.Registrators.Validate()
}
