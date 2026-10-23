package operator

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/controllers"
	"github.com/nais/sts-operator/internal/config"
	stsmetrics "github.com/nais/sts-operator/internal/metric"
	stsapi "github.com/nais/sts/api"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var scheme = runtime.NewScheme()

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(
		stsmetrics.STSClientsTotal,
		stsmetrics.STSClientsProcessedCount,
		stsmetrics.STSClientsFinalizedCount,
		stsmetrics.STSClientsProcessingFailedCount,
	)

	_ = clientgoscheme.AddToScheme(scheme)
	_ = stsv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func Run(cfg *config.Config, log *slog.Logger) error {
	if err := setupLogger(cfg.LogLevel); err != nil {
		return fmt.Errorf("set up logger: %w", err)
	}

	log.Info("starting sts-operator")
	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	mgr, err := ctrl.NewManager(kubeConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: ctrlmetricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LivenessEndpointName:   "/healthz",
		ReadinessEndpointName:  "/readyz",
		LeaderElection:         cfg.LeaderElection,
		LeaderElectionID:       "sts.nais.io",
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("register health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("register ready check: %w", err)
	}

	registrator, err := stsapi.NewRegistrationClient(stsapi.STSIssuer(cfg.STSBaseURL), stsapi.TokenFromFile(cfg.AuthTokenPath))
	if err != nil {
		return fmt.Errorf("create STS registrator: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", registrator.PublicKeySetHandler)

	if err := mgr.Add(&manager.Server{
		Name: "Public JWKS",
		Server: &http.Server{
			Addr:              cfg.JwksAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		OnlyServeWhenLeader: cfg.LeaderElection,
		ShutdownTimeout:     new(30 * time.Second),
	}); err != nil {
		return fmt.Errorf("add public jwks server: %w", err)
	}

	if err = controllers.NewSTSClientReconciler(mgr, cfg, registrator); err != nil {
		return fmt.Errorf("create STSClient reconciler: %w", err)
	}

	log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}
	return nil
}

func setupLogger(logLevel string) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
	ctrl.SetLogger(logr.FromSlogHandler(handler))

	return nil
}
