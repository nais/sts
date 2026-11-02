package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"
)

type requestMethodKey struct{}

func requestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestMethodKey{}, r.Method)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TODO: rename to something more appropriate?
type contextHandler struct {
	slog.Handler
}

func (h contextHandler) Handle(ctx context.Context, record slog.Record) error {
	span := trace.SpanContextFromContext(ctx)
	if span.IsValid() {
		record.AddAttrs(
			slog.String("trace_id", span.TraceID().String()),
			slog.String("span_id", span.SpanID().String()),
		)
	}

	if method, ok := ctx.Value(requestMethodKey{}).(string); ok {
		record.AddAttrs(slog.String("method", method))

		// chi resolves the route after middleware entry, so read it at log time.
		if route := chi.RouteContext(ctx); route != nil && route.RoutePattern() != "" {
			record.AddAttrs(slog.String("route", route.RoutePattern()))
		}
	}

	return h.Handler.Handle(ctx, record)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
