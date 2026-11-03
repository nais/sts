package sts

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// Derived loggers must keep contextHandler; otherwise the embedded handler's
// WithAttrs/WithGroup silently drop the enrichment.
func TestContextHandlerDerivedLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(contextHandler{slog.NewJSONHandler(&output, nil)}).
		With("component", "sts").WithGroup("request")
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1},
		SpanID:  trace.SpanID{2},
	})
	logger.InfoContext(trace.ContextWithSpanContext(context.Background(), span), "event")

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, "sts", record["component"])
	fields, ok := record["request"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, span.TraceID().String(), fields["trace_id"])
	assert.Equal(t, span.SpanID().String(), fields["span_id"])
}

func TestContextHandlerRequest(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(contextHandler{slog.NewJSONHandler(&output, nil)})

	router := chi.NewRouter()
	router.Post("/client/{id}", func(w http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "client registered")
		w.WriteHeader(http.StatusNoContent)
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/client/private-client?secret=hidden", nil))

	// Raw paths and query strings must never be logged.
	assert.NotContains(t, output.String(), "private-client")
	assert.NotContains(t, output.String(), "hidden")

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, http.MethodPost, record["method"])
	assert.Equal(t, "/client/{id}", record["route"])
}
