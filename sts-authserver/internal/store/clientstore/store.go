package clientstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/cache"
	"github.com/nais/sts/internal/database"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
)

const clientCacheChannel = "sts_cache_changed"

var _ oauth.ClientStore = (*Store)(nil)

// Store serves clients and policies from an atomically replaced snapshot.
type Store struct {
	pool            *pgxpool.Pool
	queries         *sqlgen.Queries
	snapshot        *cache.Snapshot[*clientSnapshot]
	listener        *cache.PostgresListener
	refreshInterval time.Duration
	log             *slog.Logger
}

func New(ctx context.Context, pool *pgxpool.Pool, refreshInterval time.Duration) (*Store, error) {
	if refreshInterval <= 0 {
		return nil, errors.New("snapshot refresh interval must be positive")
	}
	store := &Store{
		pool:            pool,
		queries:         sqlgen.New(pool),
		refreshInterval: refreshInterval,
		log:             slog.With(slog.Default(), "component", "clientstore"),
	}
	snapshot, err := cache.NewSnapshot(database.ReadOnlySnapshotLoader(pool, loadClientSnapshot))
	if err != nil {
		return nil, err
	}
	store.snapshot = snapshot
	store.listener = cache.NewPostgresListener(pool, clientCacheChannel, func(string) {
		snapshot.Trigger()
	}, store.log)

	if err := store.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialize client store: %w", err)
	}

	return store, nil
}

func (s *Store) Run(ctx context.Context) {
	var listener sync.WaitGroup
	listener.Go(func() {
		s.listener.Run(ctx)
	})

	if err := s.snapshot.RunPeriodic(ctx, s.refreshInterval, func(err error) {
		s.log.Error("refresh client cache snapshot", "error", err)
	}); err != nil {
		s.log.Error("run client cache snapshot", "error", err)
	}
	listener.Wait()
}

func (s *Store) Close() {
	s.listener.Close()
}

func (s *Store) Get(issuer, namespace, name string) (*oauth.Client, error) {
	snapshot, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("client cache is not initialized")
	}

	key := clientKey{issuer: issuer, namespace: namespace, name: name}
	row, ok := snapshot.clients[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", oauth.ErrClientNotFound, key)
	}

	return toClient(row), nil
}

func (s *Store) GetByID(clientID oauth.ClientID) (*oauth.Client, error) {
	snapshot, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("client cache is not initialized")
	}

	row, ok := snapshot.clientsById[clientID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", oauth.ErrClientNotFound, clientID)
	}

	return toClient(row), nil
}

func (s *Store) AuthorizeTarget(_ context.Context, consumer *oauth.Client, target oauth.ClientID) (oauth.Roles, error) {
	snapshot, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("client cache is not initialized")
	}
	p, ok := snapshot.policies[target]
	if !ok {
		return nil, fmt.Errorf("%w: target %q not found", oauth.ErrTargetUnauthorized, target)
	}
	if roles, ok := p.clients[consumer.ID]; ok {
		return slices.Clone(roles), nil
	}
	if _, ok := p.namespaces[consumer.Namespace]; ok {
		return nil, nil
	}
	if p.allowAll {
		return nil, nil
	}

	return nil, fmt.Errorf("%w: %s", oauth.ErrTargetUnauthorized, target)
}

// initialize subscribes before loading to avoid missing a write between the
// initial snapshot and LISTEN registration.
func (s *Store) initialize(ctx context.Context) error {
	if err := s.listener.Connect(ctx); err != nil {
		return err
	}
	if err := s.snapshot.Initialize(ctx); err != nil {
		s.listener.Close()
		return fmt.Errorf("load initial client cache snapshot: %w", err)
	}
	return nil
}

func loadClientSnapshot(ctx context.Context, queries *sqlgen.Queries) (*clientSnapshot, error) {
	clients, err := queries.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kubernetes clients: %w", err)
	}

	result := &clientSnapshot{
		clients:     make(map[clientKey]sqlgen.Client, len(clients)),
		clientsById: make(map[oauth.ClientID]sqlgen.Client, len(clients)),
		policies:    make(map[oauth.ClientID]policy, len(clients)),
	}
	for _, client := range clients {
		result.clients[clientKeyFromRow(client)] = client
		result.clientsById[client.ID] = client
		result.policies[client.ID] = newPolicy(client.AuthorizationPolicy)
	}
	return result, nil
}
