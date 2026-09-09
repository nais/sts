package config

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/joho/godotenv"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	BindAddress               string     `env:"BIND_ADDRESS, default=:8080"`
	DatabaseURL               string     `env:"DATABASE_URL, required"`
	InternalBindAddress       string     `env:"INTERNAL_BIND_ADDRESS, default=:8081"`
	LogLevel                  slog.Level `env:"LOG_LEVEL, default=info"`
	LogFormat                 string     `env:"LOG_FORMAT, default=text"`
	AuthorizationServerConfig oauth.AuthorizationServerConfig
	Registrators              []*registration.ClientRegistratorConfig // TODO: env things
}

func Load(ctx context.Context) (Config, error) {
	_ = godotenv.Load(".env")
	return loadWith(ctx, envconfig.OsLookuper())
}

func loadWith(ctx context.Context, lookuper envconfig.Lookuper) (Config, error) {
	var cfg Config
	if err := envconfig.ProcessWith(ctx, &envconfig.Config{Target: &cfg, Lookuper: lookuper}); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
	return c.AuthorizationServerConfig.Validate()
}
