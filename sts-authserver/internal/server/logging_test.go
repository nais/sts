package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

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
			logger := slog.New(traceHandler{slog.NewJSONHandler(&output, nil)})
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
		})
	}
}

func TestTraceHandlerDerivedLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(traceHandler{slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelWarn})}).
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
