package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const Algorithm = jose.ES256

var _ jose.Signer = (*Signer)(nil)

type Key struct {
	jose.JSONWebKey
}

func Generate() (Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate signing key: %w", err)
	}
	return Key{
		Key:       key,
		KeyID:     uuid.New().String(),
		Algorithm: string(Algorithm),
		Use:       oidc.KeyUseSignature,
	}, nil
}

func (k Key) Public() Key {
	return Key{JSONWebKey: k.JSONWebKey.Public()}
}

func (k Key) Signer() (*Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(k.Algorithm),
		Key:       &k.JSONWebKey,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	return &Signer{
		Signer:    signer,
		publicKey: k.Public(),
	}, nil
}

func (k Key) Verify(jws *jose.JSONWebSignature) ([]byte, error) {
	payload, err := jws.Verify(&k.JSONWebKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return payload, nil
}

type Signer struct {
	jose.Signer
	publicKey Key
}

func GenerateSigner() (*Signer, error) {
	key, err := Generate()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key.Signer()
}

func (s *Signer) Algorithm() string {
	return s.publicKey.Algorithm
}

func (s *Signer) PublicKeySet() KeySet {
	return KeySet{Keys: []jose.JSONWebKey{s.publicKey.JSONWebKey}}
}

func (s *Signer) SignJWT(claims any) (string, error) {
	return crypto.Sign(claims, s.Signer)
}

type KeySet jose.JSONWebKeySet

func (s KeySet) FindKey(jws *jose.JSONWebSignature) (*Key, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, s.Keys...)
	if err != nil {
		return nil, err
	}
	return &Key{JSONWebKey: key}, nil
}
