package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/operator"
	// +kubebuilder:scaffold:imports
)

func main() {
	ctx := context.Background()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("logger", "setup")
	cfg, err := config.New(ctx)
	if err != nil {
		log.Error("load configuration", "error", err)
		os.Exit(1)
	}

	if err := operator.Run(cfg, log); err != nil {
		log.Error("run", "error", err)
		os.Exit(1)
	}
}
