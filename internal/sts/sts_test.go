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
	t.Setenv("DATABASE_URL", "://")
	t.Setenv("CLIENT_AUTH_ISSUERS", "https://env1.example")
	t.Setenv("SUBJECT_TOKEN_ISSUERS", "https://subject.example")

	if err := Run(context.Background()); err == nil {
		t.Fatal("Run() returned nil error")
	}
	if _, ok := slog.Default().Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("logger handler is %T, want *slog.JSONHandler", slog.Default().Handler())
	}
}
