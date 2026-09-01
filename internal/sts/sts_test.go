package sts

import (
	"context"
	"log/slog"
	"testing"
)

func TestRunConfiguresJSONLogger(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("BIND_ADDRESS", "invalid")
	t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/sts?sslmode=disable")

	if err := Run(context.Background()); err == nil {
		t.Fatal("Run() returned nil error")
	}
	if _, ok := slog.Default().Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("logger handler is %T, want *slog.JSONHandler", slog.Default().Handler())
	}
}
