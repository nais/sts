package keystore

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
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
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// signingKeyLockID serializes key creation and rotation across replicas.
	signingKeyLockID = 4711

	signingKeyRetentionLeeway = 5 * time.Minute
)

var signingKeySetID = uuid.MustParse("00000000-0000-0000-0000-000000004711")

// Store signs tokens and publishes a rotating set of three signing keys.
type Store struct {
	pool             *pgxpool.Pool
	queries          *sqlgen.Queries
	rotationInterval time.Duration
	snapshot         *cache.Snapshot[*keySnapshot]
	aead             cipher.AEAD
}

type keySnapshot struct {
	signer    *jwk.Signer
	public    jwk.KeySet
	expiresAt time.Time
}

func New(ctx context.Context, pool *pgxpool.Pool, tokenTTL time.Duration, encryptionKey []byte) (*Store, error) {
	if tokenTTL <= 0 {
		return nil, fmt.Errorf("token TTL must be positive")
	}
	aead, err := chacha20poly1305.NewX(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create signing key encryptor: %w", err)
	}

	keystore := &Store{
		pool:    pool,
		queries: sqlgen.New(pool),
		aead:    aead,
		// A key remains public for one full rotation after it stops signing.
		// This must exceed the token lifetime so every live token remains verifiable.
		rotationInterval: tokenTTL + signingKeyRetentionLeeway,
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

func (s *Store) Run(ctx context.Context) error {
	for {
		current, ok := s.snapshot.Current()
		if !ok {
			return errors.New("signing key cache is not initialized")
		}

		timer := time.NewTimer(max(time.Until(current.expiresAt), 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
			if err := s.RotateSigningKeys(ctx); err != nil {
				return fmt.Errorf("rotate signing keys: %w", err)
			}
		}
	}
}

// RotateSigningKeys rotates the database key set at most once and then reloads
// this replica's snapshot. The advisory lock and expiration recheck make this
// safe when multiple replicas call it concurrently.
func (s *Store) RotateSigningKeys(ctx context.Context) error {
	if err := s.rotateSigningKeysInDatabase(ctx); err != nil {
		return err
	}
	if err := s.snapshot.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh signing keys after rotation: %w", err)
	}
	return nil
}

func (s *Store) Signer() (*jwk.Signer, error) {
	current, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return current.signer, nil
}

func (s *Store) PublicKeys() (*jwk.KeySet, error) {
	current, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return &current.public, nil
}

func (s *Store) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	key, err := s.findKey(jws)
	if err != nil {
		// Another replica may just have rotated. Refresh once before rejecting an
		// unknown key so verification does not depend on notification latency.
		if refreshErr := s.snapshot.Refresh(ctx); refreshErr != nil {
			return nil, fmt.Errorf("refresh signing keys after key miss: %w", refreshErr)
		}
		key, err = s.findKey(jws)
		if err != nil {
			return nil, fmt.Errorf("find verification key: %w", err)
		}
	}
	return key.Verify(jws)
}

// ensureInitialSigningKeys creates the first signing keys, so a fresh database can issue tokens.
func (s *Store) ensureInitialSigningKeys(ctx context.Context) error {
	return s.withSigningKeyLock(ctx, func(ctx context.Context, queries *sqlgen.Queries) error {
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

		if err := s.saveSigningKeys(ctx, queries, signingKeySetID, keys); err != nil {
			return fmt.Errorf("insert rotatable signing key: %w", err)
		}
		return nil
	})
}

func (s *Store) rotateSigningKeysInDatabase(ctx context.Context) error {
	return s.withSigningKeyLock(ctx, func(ctx context.Context, queries *sqlgen.Queries) error {
		row, err := queries.GetSigningKeySet(ctx)
		if err != nil {
			return fmt.Errorf("get signing key set: %w", err)
		}

		if time.Now().Before(row.ExpiresAt) {
			return nil
		}

		keys, err := signingKeysFromRow(row, s.aead)
		if err != nil {
			return err
		}

		rotated, err := keys.rotate()
		if err != nil {
			return err
		}

		if err := s.saveSigningKeys(ctx, queries, row.ID, rotated); err != nil {
			return fmt.Errorf("save rotated signing keys: %w", err)
		}
		return nil
	})
}

func (s *Store) saveSigningKeys(ctx context.Context, queries *sqlgen.Queries, id uuid.UUID, keys *signingKeys) error {
	previous, err := s.encryptKey(keys.previous)
	if err != nil {
		return fmt.Errorf("encrypt previous key: %w", err)
	}
	current, err := s.encryptKey(keys.current)
	if err != nil {
		return fmt.Errorf("encrypt current key: %w", err)
	}
	next, err := s.encryptKey(keys.next)
	if err != nil {
		return fmt.Errorf("encrypt next key: %w", err)
	}
	return queries.SaveSigningKeySet(ctx, sqlgen.SaveSigningKeySetParams{
		ID:          id,
		PreviousKey: previous,
		CurrentKey:  current,
		NextKey:     next,
		ExpiresAt:   time.Now().Add(s.rotationInterval),
	})
}

func (s *Store) encryptKey(key jwk.Key) ([]byte, error) {
	plaintext, err := key.MarshalJSON()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate signing key nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *Store) withSigningKeyLock(ctx context.Context, fn func(context.Context, *sqlgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin signing key transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", signingKeyLockID); err != nil {
		return fmt.Errorf("lock signing keys: %w", err)
	}
	if err := fn(ctx, s.queries.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit signing key transaction: %w", err)
	}
	return nil
}

func (s *Store) load(ctx context.Context) (*keySnapshot, error) {
	row, err := s.queries.GetSigningKeySet(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no active rotatable signing key")
	}
	if err != nil {
		return nil, fmt.Errorf("read active rotatable signing key: %w", err)
	}

	keys, err := signingKeysFromRow(row, s.aead)
	if err != nil {
		return nil, err
	}

	signer, err := keys.current.Signer()
	if err != nil {
		return nil, err
	}

	return &keySnapshot{
		signer:    signer,
		public:    keys.publicKeySet(),
		expiresAt: row.ExpiresAt,
	}, nil
}

func (s *Store) findKey(jws *jose.JSONWebSignature) (*jwk.Key, error) {
	current, ok := s.snapshot.Current()
	if !ok {
		return nil, errors.New("signing key cache is not initialized")
	}
	return current.public.FindKey(jws)
}
