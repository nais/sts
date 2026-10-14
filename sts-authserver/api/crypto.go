package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"uuid"

	"github.com/go-jose/go-jose/v4"
)

const Algorithm = jose.ES256

func sign(object any, signer jose.Signer) (string, error) {
	payload, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	if signer == nil {
		return "", errors.New("missing signer")
	}
	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return result.CompactSerialize()
}

func generateKey() (*jose.JSONWebKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &jose.JSONWebKey{
		Key:       key,
		KeyID:     uuid.New().String(),
		Algorithm: string(Algorithm),
		Use:       "sig",
	}, nil
}

func createSigner(key *jose.JSONWebKey) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: Algorithm,
		Key:       key,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, nil
}
