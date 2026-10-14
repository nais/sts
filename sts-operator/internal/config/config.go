package config

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/liberator/pkg/oauth"

	"github.com/nais/sts-operator/internal/jwk"
)

type Config struct {
	AuthTokenPath           string
	ClientID                string
	ClientJwk               *jose.JSONWebKey
	ClusterName             string
	ProbeAddr               string
	LeaderElection          bool
	LogLevel                string
	MaxConcurrentReconciles int
	MetricsAddr             string
	STSMetadata             *oauth.MetadataOAuth
}

func New(ctx context.Context) (*Config, error) {
	cfg := &Config{}
	var clientJwkJson string
	var stsURL string

	flag.StringVar(&cfg.AuthTokenPath, "auth-token-path", os.Getenv("AUTH_TOKEN_PATH"), "Path to service account token file for STS authentication. If empty, falls back to client assertion with private key.")
	flag.StringVar(&clientJwkJson, "client-jwk-json", os.Getenv("STS_OPERATOR_PRIVATE_JWK"), "json with private JWK credential")
	flag.StringVar(&cfg.ClientID, "client-id", os.Getenv("STS_OPERATOR_CLIENT_ID"), "Client ID of sts-operator at Auth Provider.")
	flag.StringVar(&cfg.ClusterName, "cluster-name", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.BoolVar(&cfg.LeaderElection, "leader-election", false, "Enable leader election for controller manager.")
	flag.StringVar(&cfg.LogLevel, "log-level", os.Getenv("LOG_LEVEL"), "Log level for sts-operator")
	flag.IntVar(&cfg.MaxConcurrentReconciles, "max-concurrent-reconciles", 20, "Max concurrent reconciles for controller.")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.ProbeAddr, "probe-addr", ":8180", "The address the health probe listener binds to.")
	flag.StringVar(&stsURL, "sts-base-url", os.Getenv("STS_URL"), "The base URL to STS.")
	flag.Parse()

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	j, err := jwk.Parse([]byte(clientJwkJson))
	if err != nil {
		return nil, err
	}
	cfg.ClientJwk = j

	maxConcurrentReconciles, ok := os.LookupEnv("STS_OPERATOR_MAX_CONCURRENT_RECONCILES")
	if ok {
		if mcr, err := strconv.Atoi(maxConcurrentReconciles); err != nil {
			cfg.MaxConcurrentReconciles = mcr
		}
	}

	stsURL = strings.TrimSpace(stsURL)
	_, err = url.Parse(stsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url for STS instance: %w", err)
	}

	// TODO: use the same logic and libs as in sts-authserver, consider creating a public client pkg in authserver for this,
	// including api generated files.
	wellKnownURL, err := oauth.MakeWellKnownURL(stsURL, oauth.WellKnownOAuthSuffix)
	if err != nil {
		return nil, fmt.Errorf("constructing well-known URL for STS %s: %w", stsURL, err)
	}

	metadata, err := oauth.NewMetadataOAuth(ctx, wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("resolving metadata for STS %s: %w", stsURL, err)
	}

	cfg.STSMetadata = metadata
	return cfg, nil
}
