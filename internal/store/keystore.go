package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TODO: review this entire file...

// signingKeyLockID guards signing key creation, so concurrent replicas create one key.
const signingKeyLockID = 4711

type PostgresKeyStore struct {
	pool      *pgxpool.Pool
	queries   *sqlgen.Queries
	cacheTTL  time.Duration
	keyExpiry time.Duration

	mu      sync.Mutex
	cache   *keyCache
	fetched time.Time
}

type keyCache struct {
	signer jose.Signer
	public jose.JSONWebKeySet

	sqlgen.RotatableSigningKey
}

func NewPostgresKeyStore(ctx context.Context, pool *pgxpool.Pool, cacheTTL time.Duration) (*PostgresKeyStore, error) {
	keystore := &PostgresKeyStore{
		pool:      pool,
		queries:   sqlgen.New(pool),
		cacheTTL:  cacheTTL,
		keyExpiry: 30 * time.Second, // TODO
	}

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

	_, err = queries.GetKeys(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read active rotatable signing key: %w", err)
	}

	// TODO: consider stronger algorithm, should be configurable and looked up from a single source of truth
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode signing key: %w", err)
	}
	if err := queries.InsertSigningKey(ctx, sqlgen.InsertSigningKeyParams{
		Kid:         uuid.New().String(),
		Algorithm:   string(jose.RS256),
		PrivateKey:  der,
		ActivatedAt: new(time.Now()),
	}); err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}

	previousKey, err := generateJwk()
	if err != nil {
		return err
	}
	currentKey, err := generateJwk()
	if err != nil {
		return err
	}
	nextKey, err := generateJwk()
	if err != nil {
		return err
	}
	if err := queries.InsertKey(ctx, sqlgen.InsertKeyParams{
		ID:          uuid.New(),
		CurrentKey:  currentKey,
		PreviousKey: previousKey,
		NextKey:     nextKey,
		Expiry:      time.Now().Add(s.keyExpiry),
	}); err != nil {
		return fmt.Errorf("insert rotatable signing key: %w", err)
	}

	return tx.Commit(ctx)
}

func generateJwk() ([]byte, error) {
	// TODO: review
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	return jose.JSONWebKey{
		Key:       key,
		KeyID:     uuid.New().String(),
		Algorithm: string(jose.RS256),
		Use:       oidc.KeyUseSignature,
	}.MarshalJSON()
}

func (s *PostgresKeyStore) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	keySet, err := s.PublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get public keys: %w", err)
	}
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keySet.Keys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return jws.Verify(&key)
}

func (s *PostgresKeyStore) load(ctx context.Context) (*keyCache, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cache != nil && time.Since(s.fetched) < s.cacheTTL {
		return s.cache, nil
	}

	rotatableKeys, err := s.queries.GetKeys(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no active rotatable signing key")
	}
	if err != nil {
		return nil, fmt.Errorf("read active rotatable signing key: %w", err)
	}

	var activeKey *jose.JSONWebKey
	err = json.Unmarshal(rotatableKeys.CurrentKey, &activeKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal current key: %w", err)
	}

	var previousKey *jose.JSONWebKey
	err = json.Unmarshal(rotatableKeys.PreviousKey, &previousKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal current key: %w", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(activeKey.Algorithm),
		Key:       activeKey,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	public := []jose.JSONWebKey{
		previousKey.Public(),
		activeKey.Public(),
	}

	s.cache = &keyCache{
		signer:              signer,
		public:              jose.JSONWebKeySet{Keys: public},
		RotatableSigningKey: rotatableKeys,
	}
	s.fetched = time.Now()
	return s.cache, nil
}
