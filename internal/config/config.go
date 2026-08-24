package config

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	BindAddress         string     `env:"BIND_ADDRESS, default=:8080"`
	InternalBindAddress string     `env:"INTERNAL_BIND_ADDRESS, default=:8081"`
	Issuer              string     `env:"ISSUER, default=http://localhost:8080"`
	LogLevel            slog.Level `env:"LOG_LEVEL, default=info"`
}

func Load(ctx context.Context) (Config, error) {
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
	if c.Issuer == "" {
		return fmt.Errorf("issuer must not be empty")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || !issuer.IsAbs() || issuer.Host == "" {
		return fmt.Errorf("issuer must be an absolute URL")
	}
	if issuer.Scheme != "https" && (issuer.Scheme != "http" || !isLoopback(issuer.Hostname())) {
		return fmt.Errorf("issuer must use https, except for localhost or loopback http URLs")
	}
	return nil
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}
