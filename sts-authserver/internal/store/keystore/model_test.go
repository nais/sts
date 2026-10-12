package keystore

import (
	"testing"

	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningKeysFromRow(t *testing.T) {
	keys, err := generateSigningKeys()
	require.NoError(t, err)

	previous := marshalKey(t, keys.previous)
	current := marshalKey(t, keys.current)
	next := marshalKey(t, keys.next)

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
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: []byte("{"), NextKey: next},
			wantErr: "unmarshal current key",
		},
		"missing key ID": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: current, NextKey: marshalKey(t, withoutKeyID)},
			wantErr: "next signing key has no key ID",
		},
		"duplicate key ID": {
			row:     sqlgen.RotatableSigningKey{PreviousKey: previous, CurrentKey: previous, NextKey: next},
			wantErr: "signing keys must have distinct key IDs",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := signingKeysFromRow(test.row)
			if test.wantErr != "" {
				assert.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, keys.current.KeyID, got.current.KeyID)
		})
	}
}

func marshalKey(t *testing.T, key jwk.Key) []byte {
	t.Helper()
	data, err := key.MarshalJSON()
	require.NoError(t, err)
	return data
}
