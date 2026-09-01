package config

import (
	"context"
	"log/slog"
	"testing"

	"github.com/sethvargo/go-envconfig"
)

func TestLoadWith(t *testing.T) {
	got, err := loadWith(context.Background(), envconfig.MapLookuper(map[string]string{
		"BIND_ADDRESS":          "127.0.0.1:9000",
		"DATABASE_URL":          "postgres://sts:secret@database:5432/sts",
		"INTERNAL_BIND_ADDRESS": "127.0.0.1:9001",
		"ISSUER":                "https://sts.example",
		"LOG_LEVEL":             "debug",
		"LOG_FORMAT":            "json",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.BindAddress != "127.0.0.1:9000" || got.DatabaseURL != "postgres://sts:secret@database:5432/sts" || got.InternalBindAddress != "127.0.0.1:9001" || got.Issuer != "https://sts.example" || got.LogLevel != slog.LevelDebug || got.LogFormat != "json" {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestLoadWithDefaults(t *testing.T) {
	got, err := loadWith(context.Background(), envconfig.MapLookuper(map[string]string{
		"DATABASE_URL": "postgres://postgres:postgres@localhost:5432/sts?sslmode=disable",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		BindAddress:         ":8080",
		DatabaseURL:         "postgres://postgres:postgres@localhost:5432/sts?sslmode=disable",
		InternalBindAddress: ":8081",
		Issuer:              "http://localhost:8080",
		LogLevel:            slog.LevelInfo,
		LogFormat:           "text",
		ExpectedAudience:    "nais",
	}
	if got != want {
		t.Fatalf("LoadWith() = %#v, want %#v", got, want)
	}
}

func TestLoadWithValidation(t *testing.T) {
	tests := map[string]map[string]string{
		"empty public address":   {"BIND_ADDRESS": ""},
		"empty database URL":     {"DATABASE_URL": ""},
		"empty internal address": {"INTERNAL_BIND_ADDRESS": ""},
		"empty issuer":           {"ISSUER": ""},
		"relative issuer":        {"ISSUER": "/issuer"},
		"http issuer":            {"ISSUER": "http://sts.example"},
		"invalid log level":      {"LOG_LEVEL": "trace"},
		"invalid log format":     {"LOG_FORMAT": "console"},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := values["DATABASE_URL"]; !ok {
				values["DATABASE_URL"] = "postgres://postgres:postgres@localhost:5432/sts?sslmode=disable"
			}
			if _, err := loadWith(context.Background(), envconfig.MapLookuper(values)); err == nil {
				t.Fatal("LoadWith() returned nil error")
			}
		})
	}
}

func TestLoadWithHTTPIssuerAllowsLoopback(t *testing.T) {
	for _, issuer := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := loadWith(context.Background(), envconfig.MapLookuper(map[string]string{
			"DATABASE_URL": "postgres://postgres:postgres@localhost:5432/sts?sslmode=disable",
			"ISSUER":       issuer,
		})); err != nil {
			t.Errorf("LoadWith(%q): %v", issuer, err)
		}
	}
}
