package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
)

// TODO: review this entire file...

// signingKeyLockID guards signing key creation, so concurrent replicas create one key.
const signingKeyLockID = 4711

type PostgresKeyStore struct {
	pool    *pgxpool.Pool
	queries *sqlgen.Queries
	ttl     time.Duration

	mu      sync.Mutex
	cache   *keyCache
	fetched time.Time
}

type keyCache struct {
	signer jose.Signer
	public jose.JSONWebKeySet
}

func NewPostgresKeyStore(ctx context.Context, pool *pgxpool.Pool, ttl time.Duration) (*PostgresKeyStore, error) {
	keystore := &PostgresKeyStore{pool: pool, queries: sqlgen.New(pool), ttl: ttl}

	err := keystore.EnsureSigningKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize keystore: %w", err)
	}
	return keystore, nil
}

func (s *PostgresKeyStore) Signer(ctx context.Context) (jose.Signer, error) {
	cache, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	return cache.signer, nil
}

func (s *PostgresKeyStore) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	cache, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	keys := cache.public
	return &keys, nil
}

// EnsureSigningKey creates the first signing key, so a fresh database can issue tokens.
func (s *PostgresKeyStore) EnsureSigningKey(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin signing key transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyLockID); err != nil {
		return fmt.Errorf("lock signing keys: %w", err)
	}

	queries := s.queries.WithTx(tx)
	_, err = queries.GetActiveSigningKey(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read active signing key: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode signing key: %w", err)
	}
	if err := queries.InsertSigningKey(ctx, sqlgen.InsertSigningKeyParams{
		Kid:         uuid.NewString(),
		Algorithm:   string(jose.RS256),
		PrivateKey:  der,
		ActivatedAt: new(time.Now()),
	}); err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresKeyStore) load(ctx context.Context) (*keyCache, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cache != nil && time.Since(s.fetched) < s.ttl {
		return s.cache, nil
	}

	active, err := s.queries.GetActiveSigningKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no active signing key")
	}
	if err != nil {
		return nil, fmt.Errorf("read active signing key: %w", err)
	}
	activeKey, err := parseSigningKey(active)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(active.Algorithm),
		Key:       activeKey,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	valid, err := s.queries.ListValidSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("read signing keys: %w", err)
	}
	public := make([]jose.JSONWebKey, 0, len(valid))
	for _, row := range valid {
		key, err := parseSigningKey(row)
		if err != nil {
			return nil, err
		}
		public = append(public, key.Public())
	}

	s.cache = &keyCache{signer: signer, public: jose.JSONWebKeySet{Keys: public}}
	s.fetched = time.Now()
	return s.cache, nil
}

func parseSigningKey(row sqlgen.SigningKey) (jose.JSONWebKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(row.PrivateKey)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("decode signing key %s: %w", row.Kid, err)
	}
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     row.Kid,
		Algorithm: row.Algorithm,
		Use:       "sig",
	}, nil
}
