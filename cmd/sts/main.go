package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts/internal/sts"
)

func main() {
	if err := sts.Run(context.Background()); err != nil {
		slog.Error("error running STS", "error", err)
		os.Exit(1)
	}
}
