package ioconvenience

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
)

func CloseWithLog(r io.Closer, log *slog.Logger) {
	if err := r.Close(); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		log.With("err", err).Warn("unable to close resource")
	}
}

func CloseFunc(ctx context.Context, f func(ctx context.Context) error) {
	if err := f(ctx); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		slog.Default().With("err", err).Warn("unable to close resource")
	}
}
