package sts

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/config"
	"go.opentelemetry.io/otel/trace"
)

type requestMethodKey struct{}

func setupLogger(cfg config.Config) {
	options := &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stderr, options)
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, options)
	}
	handler = contextHandler{handler}

	slog.SetDefault(slog.New(handler))
	slog.Info("configuration loaded",
		"bind_address", cfg.BindAddress,
		"internal_bind_address", cfg.InternalBindAddress,
		"issuer", cfg.AuthorizationServerConfig.Issuer,
		"log_level", cfg.LogLevel.String(),
		"log_format", cfg.LogFormat,
	)
}

func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestMethodKey{}, r.Method)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

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
