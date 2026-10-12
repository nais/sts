package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

func TestInternalRouterHealthAndUnavailableReadiness(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://x@127.0.0.1:1/x")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close() // Force readiness to exercise the unavailable path without network access.

	handler := internalRouter(prometheus.NewRegistry(), pool)
	tests := []struct {
		name       string
		path       string
		statusCode int
		body       string
	}{
		{name: "health", path: healthEndpoint, statusCode: http.StatusOK, body: "ok"},
		{name: "readiness", path: readinessEndpoint, statusCode: http.StatusServiceUnavailable, body: "database unavailable\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.path, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tt.statusCode {
				t.Fatalf("status = %d, want %d", response.Code, tt.statusCode)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != tt.body {
				t.Fatalf("body = %q, want %q", body, tt.body)
			}
		})
	}
}
