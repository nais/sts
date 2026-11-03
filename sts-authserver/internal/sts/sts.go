package sts

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/config"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/ioconvenience"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/store/clientstore"
	"github.com/nais/sts/internal/store/keystore"
	"golang.org/x/sync/errgroup"
)

const (
	clientCacheRefreshInterval = time.Minute
)

type STS struct {
	pool            *pgxpool.Pool
	clientStore     *clientstore.Store
	keyStore        *keystore.Store
	server          *http.Server
	internalServer  *http.Server
	metricsProvider *stsmetrics.Provider
}

func Run(ctx context.Context, cfg config.Config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	setupLogger(cfg)

	sts, err := New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create STS: %w", err)
	}
	defer ioconvenience.CloseWithLog(sts, slog.Default())

	return sts.Run(ctx)
}

func New(ctx context.Context, cfg config.Config) (*STS, error) {
	// TODO: use default metrics provider so we dont have to pass it around everywhere
	metricsProvider, err := stsmetrics.NewProvider()
	if err != nil {
		return nil, err
	}

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, slog.Default(), metricsProvider.Meter())
	if err != nil {
		return nil, err
	}

	clientStore, err := clientstore.New(ctx, pool, clientCacheRefreshInterval)
	if err != nil {
		return nil, err
	}

	keyStore, err := keystore.New(ctx, pool, cfg.AuthorizationServerConfig.TokenExpiry)
	if err != nil {
		return nil, err
	}

	api, err := stsApi(ctx, cfg, clientStore, keyStore, metricsProvider)
	if err != nil {
		return nil, err
	}

	return &STS{
		pool:            pool,
		clientStore:     clientStore,
		keyStore:        keyStore,
		server:          httpServer(cfg.BindAddress, api),
		internalServer:  httpServer(cfg.InternalBindAddress, internalApi(metricsProvider.Registry(), pool)),
		metricsProvider: metricsProvider,
	}, nil
}

func (sts *STS) Run(ctx context.Context) error {
	slog.Info("starting servers",
		"public_address", sts.server.Addr,
		"internal_address", sts.internalServer.Addr,
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		sts.clientStore.Run(groupCtx)
		return nil
	})
	group.Go(func() error { return sts.keyStore.Run(groupCtx) })
	group.Go(func() error { return serve(sts.server) })
	group.Go(func() error { return serve(sts.internalServer) })
	group.Go(func() error {
		<-groupCtx.Done()
		return shutdown(sts.server)
	})
	group.Go(func() error {
		<-groupCtx.Done()
		return shutdown(sts.internalServer)
	})
	return group.Wait()
}

func (sts *STS) Close() error {
	sts.clientStore.Close()
	sts.pool.Close()
	return nil
}
