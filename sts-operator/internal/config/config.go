package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	AuthTokenPath string `env:"AUTH_TOKEN_PATH,default=/var/run/secrets/nais.io/sts/token"`
	// LocalServiceAccount, when set to namespace/name, makes local operator runs
	// request tokens for that ServiceAccount from the apiserver instead of reading AuthTokenPath.
	LocalServiceAccount     string        `env:"LOCAL_SERVICE_ACCOUNT"`
	ClusterName             string        `env:"CLUSTER_NAME,required"`
	LogLevel                string        `env:"LOG_LEVEL,default=info"`
	MaxConcurrentReconciles int           `env:"MAX_CONCURRENT_RECONCILES,default=20"`
	ProbeAddr               string        `env:"PROBE_ADDR,default=:8180"`
	MetricsAddr             string        `env:"METRICS_ADDR,default=:8181"`
	JwksAddr                string        `env:"JWKS_ADDR,default=:8182"`
	STSBaseURL              string        `env:"STS_BASE_URL,required"`
	SyncInterval            time.Duration `env:"SYNC_INTERVAL,default=1m"`
}

func New(ctx context.Context) (*Config, error) {
	cfg := &Config{}

	err := envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:   cfg,
		Lookuper: envconfig.OsLookuper(),
	})
	if err != nil {
		return nil, fmt.Errorf("error processing configuration: %w", err)
	}

	if cfg.SyncInterval <= 0 {
		return nil, fmt.Errorf("SYNC_INTERVAL must be greater than 0, got %s", cfg.SyncInterval)
	}

	if cfg.LocalServiceAccount == "" {
		_, err = os.ReadFile(cfg.AuthTokenPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read token from %s: %w", cfg.AuthTokenPath, err)
		}
	}

	return cfg, nil
}
