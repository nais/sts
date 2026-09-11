package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	// signingKeyLockID serializes key creation and rotation across replicas.
	signingKeyLockID = 4711

	signingKeyRetentionLeeway = 5 * time.Minute
)

var signingKeySetID = uuid.MustParse("00000000-0000-0000-0000-000000004711")

type RotatingKeyStore struct {
	pool     *pgxpool.Pool
	queries  *sqlgen.Queries
	keyTTL   time.Duration
	snapshot atomic.Pointer[keyCache]
}

type keyCache struct {
	signer jose.Signer
	public jose.JSONWebKeySet

	sqlgen.RotatableSigningKey
}

func NewRotatingKeyStore(ctx context.Context, pool *pgxpool.Pool, tokenTTL time.Duration) (*RotatingKeyStore, error) {
	if tokenTTL <= 0 {
		return nil, fmt.Errorf("token TTL must be positive")
	}

	keystore := &RotatingKeyStore{
		pool:    pool,
		queries: sqlgen.New(pool),
		// A key remains public for one full rotation after it stops signing.
		// This must exceed the token lifetime so every live token remains verifiable.
		keyTTL: tokenTTL + signingKeyRetentionLeeway,
	}

	if err := keystore.ensureInitialSigningKeys(ctx); err != nil {
		return nil, fmt.Errorf("initialize keystore: %w", err)
	}
	if err := keystore.refresh(ctx); err != nil {
		return nil, fmt.Errorf("load initial signing keys: %w", err)
	}

	return keystore, nil
}

func (r *RotatingKeyStore) Run(ctx context.Context) error {
	for {
		current := r.snapshot.Load()
		if current == nil {
			return errors.New("signing key cache is not initialized")
		}

		timer := time.NewTimer(max(time.Until(current.ExpiresAt), 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
			if err := r.RotateSigningKeys(ctx); err != nil {
				return fmt.Errorf("rotate signing keys: %w", err)
			}
		}
	}
}

func (r *RotatingKeyStore) Signer() (jose.Signer, error) {
	current := r.snapshot.Load()
	if current == nil {
		return nil, errors.New("signing key cache is not initialized")
	}
	return current.signer, nil
}

func (r *RotatingKeyStore) PublicKeys() (*jose.JSONWebKeySet, error) {
	current := r.snapshot.Load()
	if current == nil {
		return nil, errors.New("signing key cache is not initialized")
	}
	return &jose.JSONWebKeySet{Keys: slices.Clone(current.public.Keys)}, nil
}

// ensureInitialSigningKeys creates the first signing keys, so a fresh database can issue tokens.
func (r *RotatingKeyStore) ensureInitialSigningKeys(ctx context.Context) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin signing key transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyLockID); err != nil {
		return fmt.Errorf("lock signing keys: %w", err)
	}

	queries := r.queries.WithTx(tx)
	_, err = queries.GetSigningKeySet(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read active rotatable signing key: %w", err)
	}

	previousKey, err := generateJWK()
	if err != nil {
		return err
	}
	currentKey, err := generateJWK()
	if err != nil {
		return err
	}
	nextKey, err := generateJWK()
	if err != nil {
		return err
	}

	if err = queries.SaveSigningKeySet(ctx, sqlgen.SaveSigningKeySetParams{
		ID:          signingKeySetID,
		CurrentKey:  currentKey,
		PreviousKey: previousKey,
		NextKey:     nextKey,
		ExpiresAt:   time.Now().Add(r.keyTTL),
	}); err != nil {
		return fmt.Errorf("insert rotatable signing key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit signing key transaction: %w", err)
	}
	return nil
}

// RotateSigningKeys rotates the database key set at most once and then reloads
// this replica's snapshot. The advisory lock and expiration recheck make this
// safe when multiple replicas call it concurrently.
func (r *RotatingKeyStore) RotateSigningKeys(ctx context.Context) error {
	if err := r.rotateSigningKeysInDatabase(ctx); err != nil {
		return err
	}
	if err := r.refresh(ctx); err != nil {
		return fmt.Errorf("refresh signing keys after rotation: %w", err)
	}
	return nil
}

func (r *RotatingKeyStore) rotateSigningKeysInDatabase(ctx context.Context) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin signing key rotation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyLockID); err != nil {
		return fmt.Errorf("lock signing keys: %w", err)
	}

	queries := r.queries.WithTx(tx)
	keySet, err := queries.GetSigningKeySet(ctx)
	if err != nil {
		return fmt.Errorf("get signing key set: %w", err)
	}

	if time.Now().Before(keySet.ExpiresAt) {
		return nil
	}

	nextKey, err := generateJWK()
	if err != nil {
		return err
	}

	if err = queries.SaveSigningKeySet(ctx, sqlgen.SaveSigningKeySetParams{
		ID:          keySet.ID,
		CurrentKey:  keySet.NextKey,
		PreviousKey: keySet.CurrentKey,
		NextKey:     nextKey,
		ExpiresAt:   time.Now().Add(r.keyTTL),
	}); err != nil {
		return fmt.Errorf("save rotated signing keys: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit signing key rotation: %w", err)
	}
	return nil
}

func (r *RotatingKeyStore) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	findKey := func() (jose.JSONWebKey, error) {
		keySet, err := r.PublicKeys()
		if err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("get public keys: %w", err)
		}
		return oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keySet.Keys...)
	}

	key, err := findKey()
	if err != nil {
		// Another replica may just have rotated. Refresh once before rejecting an
		// unknown key so verification does not depend on notification latency.
		if refreshErr := r.refresh(ctx); refreshErr != nil {
			return nil, fmt.Errorf("refresh signing keys after key miss: %w", refreshErr)
		}
		key, err = findKey()
		if err != nil {
			return nil, fmt.Errorf("find verification key: %w", err)
		}
	}

	payload, err := jws.Verify(&key)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return payload, nil
}

func (r *RotatingKeyStore) refresh(ctx context.Context) error {
	current, err := r.load(ctx)
	if err != nil {
		return err
	}
	r.snapshot.Store(current)
	return nil
}

func (r *RotatingKeyStore) load(ctx context.Context) (*keyCache, error) {
	signingKeySet, err := r.queries.GetSigningKeySet(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no active rotatable signing key")
	}
	if err != nil {
		return nil, fmt.Errorf("read active rotatable signing key: %w", err)
	}

	var activeKey jose.JSONWebKey
	if err := json.Unmarshal(signingKeySet.CurrentKey, &activeKey); err != nil {
		return nil, fmt.Errorf("unmarshal current key: %w", err)
	}
	if activeKey.Key == nil {
		return nil, errors.New("current signing key is empty")
	}

	var previousKey jose.JSONWebKey
	if err := json.Unmarshal(signingKeySet.PreviousKey, &previousKey); err != nil {
		return nil, fmt.Errorf("unmarshal previous key: %w", err)
	}
	if previousKey.Key == nil {
		return nil, errors.New("previous signing key is empty")
	}

	var nextKey jose.JSONWebKey
	if err := json.Unmarshal(signingKeySet.NextKey, &nextKey); err != nil {
		return nil, fmt.Errorf("unmarshal next key: %w", err)
	}
	if nextKey.Key == nil {
		return nil, errors.New("next signing key is empty")
	}
	if previousKey.KeyID == activeKey.KeyID || previousKey.KeyID == nextKey.KeyID || activeKey.KeyID == nextKey.KeyID {
		return nil, errors.New("signing keys must have distinct key IDs")
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(activeKey.Algorithm),
		Key:       &activeKey,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	return &keyCache{
		signer: signer,
		public: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			previousKey.Public(),
			activeKey.Public(),
			nextKey.Public(),
		}},
		RotatableSigningKey: signingKeySet,
	}, nil
}

func generateJWK() ([]byte, error) {
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
