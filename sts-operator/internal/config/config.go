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
	"github.com/nais/sts-operator/internal/sts"
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
	STSInstances            []sts.Instance
}

func New(ctx context.Context) (*Config, error) {
	cfg := &Config{}
	var clientJwkJson string
	var instanceString string
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
	flag.StringVar(&instanceString, "sts-instances", os.Getenv("STS_INSTANCES"), "Comma separated list of baseUrls to STS instances.")
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

	instances := make([]sts.Instance, 0)
	raw := strings.TrimSpace(instanceString)
	if raw == "" {
		raw = stsURL
	}
	for u := range strings.SplitSeq(raw, ",") {
		_, err := url.Parse(strings.TrimSpace(u))
		if err != nil {
			return nil, fmt.Errorf("invalid base url for STS instance: %w", err)
		}

		wellKnownURL, err := oauth.MakeWellKnownURL(u, oauth.WellKnownOAuthSuffix)
		if err != nil {
			return nil, fmt.Errorf("constructing well-known URL for STS instance %s: %w", u, err)
		}

		metadata, err := oauth.NewMetadataOAuth(ctx, wellKnownURL)
		if err != nil {
			return nil, fmt.Errorf("resolving metadata for STS instance %s: %w", u, err)
		}

		instances = append(instances, sts.NewInstance(u, cfg.ClientID, cfg.ClientJwk, metadata, cfg.AuthTokenPath))
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no STS instances configured")
	}
	cfg.STSInstances = instances

	return cfg, nil
}
