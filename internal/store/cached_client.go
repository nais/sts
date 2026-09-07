package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/cache"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const clientCacheChannel = "sts_cache_changed"

type policyKey struct {
	owner    string
	consumer string
}

type clientSnapshot struct {
	clients  map[clientKey]sqlgen.KubernetesClient
	policies map[policyKey]oauth.Roles
}

// CachedClient serves clients and policies from an atomically replaced snapshot.
type CachedClient struct {
	pool     *pgxpool.Pool
	queries  *sqlgen.Queries
	snapshot *cache.Snapshot[*clientSnapshot]
	listener *cache.PostgresListener
	log      *slog.Logger
}

func NewCachedClientStore(pool *pgxpool.Pool, refreshInterval time.Duration, log *slog.Logger) (*CachedClient, error) {
	store := &CachedClient{pool: pool, queries: sqlgen.New(pool), log: log}
	snapshot, err := cache.NewSnapshot(store.load, refreshInterval)
	if err != nil {
		return nil, err
	}
	store.snapshot = snapshot
	store.listener = cache.NewPostgresListener(pool, clientCacheChannel, func(string) {
		snapshot.Trigger()
	}, log)
	return store, nil
}

var _ oauth.ClientStore = (*CachedClient)(nil)

// Initialize subscribes before loading to avoid missing a write between the
// initial snapshot and LISTEN registration.
func (s *CachedClient) Initialize(ctx context.Context) error {
	if err := s.listener.Connect(ctx); err != nil {
		return err
	}
	if err := s.snapshot.Initialize(ctx); err != nil {
		s.listener.Close()
		return fmt.Errorf("load initial client cache snapshot: %w", err)
	}
	return nil
}

func (s *CachedClient) Close() {
	s.listener.Close()
}

func (s *CachedClient) Run(ctx context.Context) {
	var listener sync.WaitGroup
	listener.Add(1)
	go func() {
		defer listener.Done()
		s.listener.Run(ctx)
	}()

	s.snapshot.Run(ctx, func(err error) {
		s.log.Error("refresh client cache snapshot", "error", err)
	})
	listener.Wait()
}

func (s *CachedClient) Get(ctx context.Context, claims *oauth.AccessTokenClaims) (*oauth.Client, error) {
	key, err := clientKeyFromClaims(claims)
	if err != nil {
		return nil, err
	}

	snapshot, ok := s.snapshot.Current()
	if !ok {
		return nil, oidc.ErrServerError().WithDescription("client cache is not initialized")
	}
	row, ok := snapshot.clients[key]
	if !ok {
		return s.getClientFromPostgres(ctx, key)
	}
	row.AllowedScopes = slices.Clone(row.AllowedScopes)
	return toClient(row), nil
}

func (s *CachedClient) Save(ctx context.Context, client *oauth.Client) error {
	return s.queries.UpsertKubernetesClient(ctx, sqlgen.UpsertKubernetesClientParams{
		ID:            client.ID,
		Environment:   client.Environment,
		Namespace:     client.Namespace,
		Workload:      client.Workload,
		Issuer:        client.Issuer,
		AllowedScopes: client.AllowedScopes,
	})
}

func (s *CachedClient) AuthorizeTarget(ctx context.Context, clientID oauth.ClientID, target oauth.Target) (oauth.Roles, error) {
	snapshot, ok := s.snapshot.Current()
	if !ok {
		return nil, oidc.ErrServerError().WithDescription("client cache is not initialized")
	}
	key := policyKey{owner: string(clientID), consumer: target.GetValue()}
	roles, ok := snapshot.policies[key]
	if !ok {
		return s.getPolicyFromPostgres(ctx, key)
	}
	return slices.Clone(roles), nil
}

func (s *CachedClient) getClientFromPostgres(ctx context.Context, key clientKey) (*oauth.Client, error) {
	row, err := s.queries.GetKubernetesClient(ctx, sqlgen.GetKubernetesClientParams{
		Issuer:    key.issuer,
		Namespace: key.namespace,
		Workload:  key.workload,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrInvalidClient().WithDescription("client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("read client after cache miss: %w", err)
	}

	// A missed notification may have caused this fallback. Refresh the complete
	// snapshot so later requests can use the cache again.
	s.snapshot.Trigger()
	return toClient(row), nil
}

func (s *CachedClient) getPolicyFromPostgres(ctx context.Context, key policyKey) (oauth.Roles, error) {
	row, err := s.queries.GetAuthorizationPolicy(ctx, sqlgen.GetAuthorizationPolicyParams{
		OwnerClientID:    key.owner,
		ConsumerClientID: key.consumer,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oidc.ErrInvalidClient().WithDescription("authorization policy not found")
	}
	if err != nil {
		return nil, oidc.ErrServerError().WithDescription("read authorization policy after cache miss: %s", err)
	}

	s.snapshot.Trigger()
	return row.Roles, nil
}

func (s *CachedClient) load(ctx context.Context) (*clientSnapshot, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin client cache snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	queries := sqlgen.New(tx)
	clients, err := queries.ListKubernetesClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kubernetes clients: %w", err)
	}
	policies, err := queries.ListAuthorizationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list authorization policies: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit client cache snapshot: %w", err)
	}

	result := &clientSnapshot{
		clients:  make(map[clientKey]sqlgen.KubernetesClient, len(clients)),
		policies: make(map[policyKey]oauth.Roles, len(policies)),
	}
	for _, client := range clients {
		result.clients[clientKey{
			issuer:    client.Issuer,
			namespace: client.Namespace,
			workload:  client.Workload,
		}] = client
	}
	for _, policy := range policies {
		result.policies[policyKey{
			owner:    policy.OwnerClientID,
			consumer: policy.ConsumerClientID,
		}] = policy.Roles
	}
	return result, nil
}
