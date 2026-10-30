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
	tests := []struct {
		name      string
		value     string // empty leaves SYNC_INTERVAL unset so the default applies
		want      time.Duration
		wantErr   bool
		errSubstr string
	}{
		{name: "defaults to one minute", want: time.Minute},
		{name: "accepts custom duration", value: "7m30s", want: 7*time.Minute + 30*time.Second},
		{name: "rejects zero", value: "0s", wantErr: true, errSubstr: "SYNC_INTERVAL must be greater than 0"},
		{name: "rejects negative", value: "-1m", wantErr: true, errSubstr: "SYNC_INTERVAL must be greater than 0"},
		{name: "rejects malformed duration", value: "soon", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredEnv(t)
			// Token file is missing, so use a local service account to skip the token check.
			t.Setenv("LOCAL_SERVICE_ACCOUNT", "ns/sa")
			if tt.value != "" {
				t.Setenv("SYNC_INTERVAL", tt.value)
			}
			cfg, err := New(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("New error = %v, want substring %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if cfg.SyncInterval != tt.want {
				t.Errorf("SyncInterval = %s, want %s", cfg.SyncInterval, tt.want)
			}
		})
	}
}
