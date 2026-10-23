package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nais/sts-operator/internal/config"
	stsapi "github.com/nais/sts/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const (
	localTokenAudience = "nais"
	localTokenTTLSecs  = 3600
	localTokenTimeout  = 10 * time.Second
)

// authTokenCallback returns the registrator's auth token source. Production reads
// cfg.AuthTokenPath. When cfg.LocalServiceAccount is set, each call requests a
// fresh token for that ServiceAccount from the apiserver; this is for local
// debugging only, so it has no caching or refresh.
func authTokenCallback(cfg *config.Config, kubeConfig *rest.Config) (stsapi.AuthTokenCallback, error) {
	if cfg.LocalServiceAccount == "" {
		return stsapi.TokenFromFile(cfg.AuthTokenPath), nil
	}

	namespace, name, err := parseServiceAccount(cfg.LocalServiceAccount)
	if err != nil {
		return nil, err
	}

	// Copy so the manager's rest.Config keeps its own timeout.
	tokenConfig := rest.CopyConfig(kubeConfig)
	tokenConfig.Timeout = localTokenTimeout
	tokenConfig.ContentType = "application/json"
	client, err := corev1.NewForConfig(tokenConfig)
	if err != nil {
		return nil, fmt.Errorf("create apiserver client for local service account: %w", err)
	}

	serviceAccounts := client.ServiceAccounts(namespace)
	return func(ctx context.Context) (string, error) {
		expirationSeconds := int64(localTokenTTLSecs)
		resp, err := serviceAccounts.CreateToken(ctx, name, &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				Audiences:         []string{localTokenAudience},
				ExpirationSeconds: &expirationSeconds,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return "", fmt.Errorf("create token for local service account %s/%s: %w", namespace, name, err)
		}
		if resp.Status.Token == "" {
			return "", fmt.Errorf("apiserver returned empty token for local service account %s/%s", namespace, name)
		}
		return resp.Status.Token, nil
	}, nil
}

// parseServiceAccount splits a namespace/name value and rejects anything else.
func parseServiceAccount(value string) (string, string, error) {
	if strings.Count(value, "/") != 1 {
		return "", "", fmt.Errorf("local service account must be namespace/name, got %q", value)
	}
	namespace, name, _ := strings.Cut(value, "/")
	if namespace == "" || name == "" {
		return "", "", fmt.Errorf("local service account must be namespace/name, got %q", value)
	}
	return namespace, name, nil
}
