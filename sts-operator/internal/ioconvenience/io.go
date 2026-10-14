package ioconvenience

import (
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
