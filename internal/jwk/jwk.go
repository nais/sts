// Package jwk creates and verifies signatures with JSON Web Keys.
package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const Algorithm = jose.ES256

func Generate() (jose.JSONWebKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("generate signing key: %w", err)
	}
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     uuid.New().String(),
		Algorithm: string(Algorithm),
		Use:       oidc.KeyUseSignature,
	}, nil
}

// NewSigner returns a signer that sets the key ID of key in each signature header.
func NewSigner(key jose.JSONWebKey) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: &key}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, nil
}

type KeySet jose.JSONWebKeySet

func (s KeySet) VerifySignature(_ context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	key, err := s.Key(jws)
	if err != nil {
		return nil, fmt.Errorf("find verification key: %w", err)
	}
	return Verify(jws, key)
}

func (s KeySet) Key(jws *jose.JSONWebSignature) (jose.JSONWebKey, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	return oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, s.Keys...)
}

func Verify(jws *jose.JSONWebSignature, key jose.JSONWebKey) ([]byte, error) {
	payload, err := jws.Verify(&key)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return payload, nil
}
