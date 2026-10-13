package keystore

import (
	"crypto/cipher"
	"crypto/rand"
	"testing"
	"time"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestSigningKeysFromRow(t *testing.T) {
	keys, err := generateSigningKeys()
	require.NoError(t, err)
	aead, err := chacha20poly1305.NewX(make([]byte, chacha20poly1305.KeySize))
	require.NoError(t, err)

	previous := encryptTestKey(t, aead, keys.previous)
	current := encryptTestKey(t, aead, keys.current)
	next := encryptTestKey(t, aead, keys.next)
	tampered := append([]byte(nil), current...)
	tampered[len(tampered)-1] ^= 1

	withoutKeyID := keys.next
	withoutKeyID.KeyID = ""

	for name, test := range map[string]struct {
		row     sqlgen.RotatableSigningKey
		wantErr string
	}{
		"valid": {
			row: sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: current, NextKey: next},
		},
		"malformed key": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: encryptTestData(t, aead, []byte("{")), NextKey: next},
			wantErr: "unmarshal current key",
		},
		"plaintext key rejected": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: marshalKey(t, keys.current), NextKey: next},
			wantErr: "decrypt current key",
		},
		"short ciphertext": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: []byte("short"), NextKey: next},
			wantErr: "ciphertext is too short",
		},
		"tampered ciphertext": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: tampered, NextKey: next},
			wantErr: "authentication failed",
		},
		"missing key ID": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: current, NextKey: encryptTestKey(t, aead, withoutKeyID)},
			wantErr: "next signing key has no key ID",
		},
		"duplicate key ID": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: previous, NextKey: next},
			wantErr: "signing keys must have distinct key IDs",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := signingKeysFromRow(test.row, aead)
			if test.wantErr != "" {
				assert.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, keys.current.KeyID, got.current.KeyID)
		})
	}
}

func TestSigningKeysFromRowRejectsWrongKey(t *testing.T) {
	keys, err := generateSigningKeys()
	require.NoError(t, err)
	aead, err := chacha20poly1305.NewX(make([]byte, chacha20poly1305.KeySize))
	require.NoError(t, err)
	wrongKey := make([]byte, chacha20poly1305.KeySize)
	wrongKey[0] = 1
	wrongAEAD, err := chacha20poly1305.NewX(wrongKey)
	require.NoError(t, err)
	row := sqlgen.RotatableSigningKey{
		PreviousKey: encryptTestKey(t, aead, keys.previous),
		CurrentKey:  encryptTestKey(t, aead, keys.current),
		NextKey:     encryptTestKey(t, aead, keys.next),
	}
	_, err = signingKeysFromRow(row, wrongAEAD)
	require.ErrorContains(t, err, "authentication failed")
}

func TestNewRejectsWrongKeyLengthBeforeDatabaseAccess(t *testing.T) {
	_, err := New(t.Context(), nil, time.Minute, []byte("too short"))
	require.ErrorContains(t, err, "create signing key encryptor")
}

func encryptTestKey(t *testing.T, aead cipher.AEAD, key jwk.Key) []byte {
	t.Helper()
	return encryptTestData(t, aead, marshalKey(t, key))
}

func encryptTestData(t *testing.T, aead cipher.AEAD, data []byte) []byte {
	t.Helper()
	nonce := make([]byte, aead.NonceSize())
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	return aead.Seal(nonce, nonce, data, nil)
}

func marshalKey(t *testing.T, key jwk.Key) []byte {
	t.Helper()
	data, err := key.MarshalJSON()
	require.NoError(t, err)
	return data
}
