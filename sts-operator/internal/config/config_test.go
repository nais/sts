package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CLUSTER_NAME", "dev")
	t.Setenv("STS_BASE_URL", "https://sts.example")
	t.Setenv("AUTH_TOKEN_PATH", filepath.Join(t.TempDir(), "missing-token"))
	t.Setenv("LOCAL_SERVICE_ACCOUNT", "")
	unsetSyncInterval(t)
}

// unsetSyncInterval makes the default apply; an empty value would parse as 0s.
func unsetSyncInterval(t *testing.T) {
	t.Helper()
	t.Setenv("SYNC_INTERVAL", "")
	if err := os.Unsetenv("SYNC_INTERVAL"); err != nil {
		t.Fatal(err)
	}
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

func TestNew_SyncInterval(t *testing.T) {
	// Token file is missing, so use a local service account to skip the token check.
	setSyncIntervalEnv := func(t *testing.T, value string) {
		t.Helper()
		setRequiredEnv(t)
		t.Setenv("LOCAL_SERVICE_ACCOUNT", "ns/sa")
		if value == "" {
			unsetSyncInterval(t)
			return
		}
		t.Setenv("SYNC_INTERVAL", value)
	}

	t.Run("defaults to one minute", func(t *testing.T) {
		setSyncIntervalEnv(t, "")
		cfg, err := New(context.Background())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if cfg.SyncInterval != time.Minute {
			t.Errorf("SyncInterval = %s, want 1m0s", cfg.SyncInterval)
		}
	})

	t.Run("accepts custom duration", func(t *testing.T) {
		setSyncIntervalEnv(t, "7m30s")
		cfg, err := New(context.Background())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if cfg.SyncInterval != 7*time.Minute+30*time.Second {
			t.Errorf("SyncInterval = %s, want 7m30s", cfg.SyncInterval)
		}
	})

	for _, value := range []string{"0s", "-1m"} {
		t.Run("rejects non-positive "+value, func(t *testing.T) {
			setSyncIntervalEnv(t, value)
			_, err := New(context.Background())
			if err == nil || !strings.Contains(err.Error(), "SYNC_INTERVAL must be greater than 0") {
				t.Fatalf("New error = %v, want SYNC_INTERVAL validation error", err)
			}
		})
	}

	t.Run("rejects malformed duration", func(t *testing.T) {
		setSyncIntervalEnv(t, "soon")
		if _, err := New(context.Background()); err == nil {
			t.Fatal("expected error for malformed SYNC_INTERVAL")
		}
	})
}
