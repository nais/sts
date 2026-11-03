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
	"github.com/nais/sts/internal/errs"
	stshttp "github.com/nais/sts/internal/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestTraceHandler(t *testing.T) {
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1},
		SpanID:  trace.SpanID{2},
	})
	child := parent.WithSpanID(trace.SpanID{3})
	for _, test := range []struct {
		name string
		span trace.SpanContext
	}{
		{name: "without span"},
		{name: "unsampled span", span: parent},
		{name: "sampled span", span: parent.WithTraceFlags(trace.FlagsSampled)},
		{name: "child span", span: child},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(contextHandler{slog.NewJSONHandler(&output, nil)})
			ctx := trace.ContextWithSpanContext(context.Background(), parent)
			ctx = trace.ContextWithSpanContext(ctx, test.span)
			logger.InfoContext(ctx, "event")

			var record map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			if test.span.IsValid() {
				assert.Equal(t, test.span.TraceID().String(), record["trace_id"])
				assert.Equal(t, test.span.SpanID().String(), record["span_id"])
			} else {
				assert.NotContains(t, record, "trace_id")
				assert.NotContains(t, record, "span_id")
			}
			assert.NotContains(t, record, "method")
			assert.NotContains(t, record, "route")
		})
	}
}

func TestTraceHandlerDerivedLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(contextHandler{slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelWarn})}).
		With("component", "sts").WithGroup("request").With("operation", "token")
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1},
		SpanID:  trace.SpanID{2},
	})
	ctx := trace.ContextWithSpanContext(context.Background(), span)
	logger.InfoContext(ctx, "filtered")
	assert.Empty(t, output.String())
	logger.WarnContext(ctx, "event")

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, "sts", record["component"])
	fields, ok := record["request"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "token", fields["operation"])
	assert.Equal(t, span.TraceID().String(), fields["trace_id"])
	assert.Equal(t, span.SpanID().String(), fields["span_id"])
}

func TestRequestLogContext(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(contextHandler{slog.NewJSONHandler(&output, nil)}))
	t.Cleanup(func() { slog.SetDefault(previous) })

	router := chi.NewRouter()
	router.Use(RequestLogging)
	router.Post("/client/{id}", func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "client registered", "client_id", "verified-client")
		w.WriteHeader(http.StatusNoContent)
	})
	router.Delete("/client/{id}", stshttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		slog.InfoContext(r.Context(), "client operation", "client_id", "verified-client")
		return errs.InvalidRequest(nil, "invalid client")
	}))
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "unmatched request")
		w.WriteHeader(http.StatusNotFound)
	})

	for _, test := range []struct {
		method string
		path   string
		status int
		route  string
		logs   int
	}{
		{method: http.MethodPost, path: "/client/private-client?secret=hidden", status: http.StatusNoContent, route: "/client/{id}", logs: 1},
		{method: http.MethodDelete, path: "/client/private-client?secret=hidden", status: http.StatusBadRequest, route: "/client/{id}", logs: 2},
		{method: http.MethodGet, path: "/unknown?secret=hidden", status: http.StatusNotFound, logs: 1},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			output.Reset()
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			assert.Equal(t, test.status, response.Code)
			assert.NotContains(t, output.String(), "private-client")
			assert.NotContains(t, output.String(), "hidden")

			decoder := json.NewDecoder(&output)
			for range test.logs {
				var record map[string]any
				require.NoError(t, decoder.Decode(&record))
				assert.Equal(t, test.method, record["method"])
				if test.route == "" {
					assert.NotContains(t, record, "route")
				} else {
					assert.Equal(t, test.route, record["route"])
				}
			}
		})
	}
}
