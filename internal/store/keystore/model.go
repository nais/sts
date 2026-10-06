package keystore

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/database/sqlgen"
	"github.com/nais/sts/internal/jwk"
)

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
