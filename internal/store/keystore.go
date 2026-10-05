package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/sts/internal/cache"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/jwk"
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
	snapshot *cache.Snapshot[*keyCache]
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
	snapshot, err := cache.NewSnapshot(keystore.load)
	if err != nil {
		return nil, fmt.Errorf("create signing key cache: %w", err)
	}
	keystore.snapshot = snapshot

	if err := keystore.ensureInitialSigningKeys(ctx); err != nil {
		return nil, fmt.Errorf("initialize keystore: %w", err)
	}
	if err := keystore.snapshot.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("load initial signing keys: %w", err)
	}

	return keystore, nil
}

func (r *RotatingKeyStore) Run(ctx context.Context) error {
	for {
		current, ok := r.snapshot.Current()
		if !ok {
			return errors.New("signing key cache is not initialized")
		}

		timer := time.NewTimer(max(time.Until(current.expiresAt), 0))
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

// RotateSigningKeys rotates the database key set at most once and then reloads
// this replica's snapshot. The advisory lock and expiration recheck make this
// safe when multiple replicas call it concurrently.
func (r *RotatingKeyStore) RotateSigningKeys(ctx context.Context) error {
	if err := r.rotateSigningKeysInDatabase(ctx); err != nil {
		return err
	}
	if err := r.snapshot.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh signing keys after rotation: %w", err)
	}
	return nil
}

func (r *RotatingKeyStore) Signer() (*jwk.Signer, error) {
	current, ok := r.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return current.signer, nil
}

func (r *RotatingKeyStore) PublicKeys() (*jwk.KeySet, error) {
	current, ok := r.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return &current.public, nil
}

func (r *RotatingKeyStore) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	key, err := r.findKey(jws)
	if err != nil {
		// Another replica may just have rotated. Refresh once before rejecting an
		// unknown key so verification does not depend on notification latency.
		if refreshErr := r.snapshot.Refresh(ctx); refreshErr != nil {
			return nil, fmt.Errorf("refresh signing keys after key miss: %w", refreshErr)
		}
		key, err = r.findKey(jws)
		if err != nil {
			return nil, fmt.Errorf("find verification key: %w", err)
		}
	}
	return key.Verify(jws)
}

// ensureInitialSigningKeys creates the first signing keys, so a fresh database can issue tokens.
func (r *RotatingKeyStore) ensureInitialSigningKeys(ctx context.Context) error {
	return r.withSigningKeyLock(ctx, func(ctx context.Context, queries *sqlgen.Queries) error {
		_, err := queries.GetSigningKeySet(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read active rotatable signing key: %w", err)
		}

		keys, err := generateSigningKeys()
		if err != nil {
			return err
		}

		if err := r.saveSigningKeys(ctx, queries, signingKeySetID, keys); err != nil {
			return fmt.Errorf("insert rotatable signing key: %w", err)
		}
		return nil
	})
}

func (r *RotatingKeyStore) rotateSigningKeysInDatabase(ctx context.Context) error {
	return r.withSigningKeyLock(ctx, func(ctx context.Context, queries *sqlgen.Queries) error {
		row, err := queries.GetSigningKeySet(ctx)
		if err != nil {
			return fmt.Errorf("get signing key set: %w", err)
		}

		if time.Now().Before(row.ExpiresAt) {
			return nil
		}

		keys, err := signingKeysFromRow(row)
		if err != nil {
			return err
		}

		rotated, err := keys.rotate()
		if err != nil {
			return err
		}

		if err := r.saveSigningKeys(ctx, queries, row.ID, rotated); err != nil {
			return fmt.Errorf("save rotated signing keys: %w", err)
		}
		return nil
	})
}

func (r *RotatingKeyStore) saveSigningKeys(ctx context.Context, queries *sqlgen.Queries, id uuid.UUID, keys *signingKeys) error {
	previous, err := keys.previous.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal previous key: %w", err)
	}
	current, err := keys.current.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal current key: %w", err)
	}
	next, err := keys.next.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal next key: %w", err)
	}
	return queries.SaveSigningKeySet(ctx, sqlgen.SaveSigningKeySetParams{
		ID:          id,
		PreviousKey: previous,
		CurrentKey:  current,
		NextKey:     next,
		ExpiresAt:   time.Now().Add(r.keyTTL),
	})
}

func (r *RotatingKeyStore) withSigningKeyLock(ctx context.Context, fn func(context.Context, *sqlgen.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin signing key transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyLockID); err != nil {
		return fmt.Errorf("lock signing keys: %w", err)
	}
	if err := fn(ctx, r.queries.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit signing key transaction: %w", err)
	}
	return nil
}

type keyCache struct {
	signer    *jwk.Signer
	public    jwk.KeySet
	expiresAt time.Time
}

func (r *RotatingKeyStore) load(ctx context.Context) (*keyCache, error) {
	row, err := r.queries.GetSigningKeySet(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no active rotatable signing key")
	}
	if err != nil {
		return nil, fmt.Errorf("read active rotatable signing key: %w", err)
	}

	keys, err := signingKeysFromRow(row)
	if err != nil {
		return nil, err
	}

	signer, err := keys.current.Signer()
	if err != nil {
		return nil, err
	}

	return &keyCache{
		signer:    signer,
		public:    keys.publicKeySet(),
		expiresAt: row.ExpiresAt,
	}, nil
}

func (r *RotatingKeyStore) findKey(jws *jose.JSONWebSignature) (*jwk.Key, error) {
	current, ok := r.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return current.public.FindKey(jws)
}

type signingKeys struct {
	previous, current, next jwk.Key
}

func generateSigningKeys() (*signingKeys, error) {
	previous, err := jwk.Generate()
	if err != nil {
		return nil, err
	}
	current, err := jwk.Generate()
	if err != nil {
		return nil, err
	}
	next, err := jwk.Generate()
	if err != nil {
		return nil, err
	}

	return &signingKeys{previous: previous, current: current, next: next}, nil
}

func signingKeysFromRow(row sqlgen.RotatableSigningKey) (*signingKeys, error) {
	var keys signingKeys
	for _, field := range []struct {
		name string
		raw  []byte
		key  *jwk.Key
	}{
		{name: "current", raw: row.CurrentKey, key: &keys.current},
		{name: "previous", raw: row.PreviousKey, key: &keys.previous},
		{name: "next", raw: row.NextKey, key: &keys.next},
	} {
		if err := json.Unmarshal(field.raw, field.key); err != nil {
			return nil, fmt.Errorf("unmarshal %s key: %w", field.name, err)
		}
		if field.key.Key == nil {
			return nil, fmt.Errorf("%s signing key is empty", field.name)
		}
		if field.key.KeyID == "" {
			return nil, fmt.Errorf("%s signing key has no key ID", field.name)
		}
	}
	if keys.previous.KeyID == keys.current.KeyID || keys.previous.KeyID == keys.next.KeyID || keys.current.KeyID == keys.next.KeyID {
		return nil, errors.New("signing keys must have distinct key IDs")
	}
	return &keys, nil
}

func (k signingKeys) rotate() (*signingKeys, error) {
	next, err := jwk.Generate()
	if err != nil {
		return nil, err
	}
	return &signingKeys{previous: k.current, current: k.next, next: next}, nil
}

func (k signingKeys) publicKeySet() jwk.KeySet {
	return jwk.KeySet{Keys: []jose.JSONWebKey{
		k.previous.Public().JSONWebKey,
		k.current.Public().JSONWebKey,
		k.next.Public().JSONWebKey,
	}}
}
