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
		"INTERNAL_BIND_ADDRESS": "127.0.0.1:9001",
		"ISSUER":                "https://sts.example",
		"LOG_LEVEL":             "debug",
		"REGISTRATIONS_FILE":    "testdata/registrations.yaml",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.BindAddress != "127.0.0.1:9000" || got.InternalBindAddress != "127.0.0.1:9001" || got.Issuer != "https://sts.example" || got.LogLevel != slog.LevelDebug || got.RegistrationsFile != "testdata/registrations.yaml" {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestLoadWithDefaults(t *testing.T) {
	got, err := loadWith(context.Background(), envconfig.MapLookuper(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{BindAddress: ":8080", InternalBindAddress: ":8081", Issuer: "http://localhost:8080", LogLevel: slog.LevelInfo, RegistrationsFile: "registrations.yaml"}
	if got != want {
		t.Fatalf("LoadWith() = %#v, want %#v", got, want)
	}
}

func TestLoadWithValidation(t *testing.T) {
	tests := map[string]map[string]string{
		"empty public address":   {"BIND_ADDRESS": ""},
		"empty internal address": {"INTERNAL_BIND_ADDRESS": ""},
		"empty issuer":           {"ISSUER": ""},
		"relative issuer":        {"ISSUER": "/issuer"},
		"http issuer":            {"ISSUER": "http://sts.example"},
		"invalid log level":      {"LOG_LEVEL": "trace"},
		"empty registrations":    {"REGISTRATIONS_FILE": ""},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadWith(context.Background(), envconfig.MapLookuper(values)); err == nil {
				t.Fatal("LoadWith() returned nil error")
			}
		})
	}
}

func TestLoadWithHTTPIssuerAllowsLoopback(t *testing.T) {
	for _, issuer := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := loadWith(context.Background(), envconfig.MapLookuper(map[string]string{"ISSUER": issuer})); err != nil {
			t.Errorf("LoadWith(%q): %v", issuer, err)
		}
	}
}
