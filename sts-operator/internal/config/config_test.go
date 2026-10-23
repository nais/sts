package config

import (
	"context"
	"path/filepath"
	"testing"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CLUSTER_NAME", "dev")
	t.Setenv("STS_BASE_URL", "https://sts.example")
	t.Setenv("AUTH_TOKEN_PATH", filepath.Join(t.TempDir(), "missing-token"))
	t.Setenv("LOCAL_SERVICE_ACCOUNT", "")
}

func TestNew_RequiresTokenFileByDefault(t *testing.T) {
	setRequiredEnv(t)
	if _, err := New(context.Background()); err == nil {
		t.Fatal("expected error when token file is missing and no local service account is set")
	}
}

func TestNew_LocalServiceAccountSkipsTokenFile(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("LOCAL_SERVICE_ACCOUNT", "ns/sa")
	cfg, err := New(context.Background())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cfg.LocalServiceAccount != "ns/sa" {
		t.Errorf("LocalServiceAccount = %q", cfg.LocalServiceAccount)
	}
}
