package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	oauthclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Issuer string

type MultiIssuerTokenVerifier map[Issuer]*TokenVerifier

func NewMultiIssuerTokenVerifier(verifiers ...*TokenVerifier) (MultiIssuerTokenVerifier, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("no verifiers configured")
	}
	verifier := make(MultiIssuerTokenVerifier, len(verifiers))
	for _, v := range verifiers {
		if err := verifier.Add(v); err != nil {
			return nil, err
		}
	}
	return verifier, nil
}

func (v MultiIssuerTokenVerifier) Add(i *TokenVerifier) error {
	_, ok := v[i.issuer]
	if ok {
		return fmt.Errorf("duplicate issuer %q", i.issuer)
	}
	v[i.issuer] = i
	return nil
}

type VerifyFn func(claims *AccessTokenClaims) error

func (v MultiIssuerTokenVerifier) Verify(ctx context.Context, rawToken string, fns ...VerifyFn) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}

	verifier, ok := v[Issuer(claims.Issuer)]
	if !ok {
		return nil, fmt.Errorf("issuer %q not supported", claims.Issuer)
	}

	verifiedClaims, err := verifier.Verify(ctx, rawToken, payload, claims)
	if err != nil {
		return nil, err
	}

	for _, fn := range fns {
		if err := fn(verifiedClaims); err != nil {
			return nil, err
		}
	}
	return verifiedClaims, nil
}

func NewTokenExchangeTokenVerifier(ctx context.Context, cfg AuthorizationServerConfig, keyStore KeyStore) (MultiIssuerTokenVerifier, error) {
	subjectTokenVerifiers, err := ExternalTokenVerifiers(ctx, cfg.SubjectTokenIssuers...)
	if err != nil {
		return nil, fmt.Errorf("resolving subject token verifiers: %w", err)
	}
	return NewMultiIssuerTokenVerifier(append(
		subjectTokenVerifiers,
		InternalTokenVerifier(cfg, keyStore),
	)...)
}

func NewClientAuthTokenVerifier(ctx context.Context, issuers []Issuer) (MultiIssuerTokenVerifier, error) {
	clientAuthVerifiers, err := ExternalTokenVerifiers(ctx, issuers...)
	if err != nil {
		return nil, fmt.Errorf("resolving client auth verifiers: %w", err)
	}
	return NewMultiIssuerTokenVerifier(clientAuthVerifiers...)
}

type TokenVerifier struct {
	issuer       Issuer
	keyset       oidc.KeySet
	requiredAlgs []string
}

func (i *TokenVerifier) Verify(ctx context.Context, rawToken string, payload []byte, claims *AccessTokenClaims) (*AccessTokenClaims, error) {
	const SkewTime = time.Minute

	if claims.Issuer != string(i.issuer) {
		return nil, oidc.ErrIssuerInvalid
	}
	if err := oidc.CheckSignature(ctx, rawToken, payload, claims, i.requiredAlgs, i.keyset); err != nil {
		return nil, err
	}
	if err := oidc.CheckExpiration(claims, SkewTime); err != nil {
		return nil, err
	}
	if err := oidc.CheckIssuedAt(claims, 0, SkewTime); err != nil {
		return nil, err
	}
	if err := oidc.CheckSubject(claims); err != nil {
		return nil, err
	}
	if !claims.NotBefore.AsTime().IsZero() {
		nowWithOffset := time.Now().Add(SkewTime).Round(time.Second)
		if claims.NotBefore.AsTime().After(nowWithOffset) {
			return nil, fmt.Errorf("nbf is in the future: (nbf: %v, now with offset: %v)", claims.NotBefore, nowWithOffset)
		}
	}
	return claims, nil
}

func InternalTokenVerifier(cfg AuthorizationServerConfig, keyStore KeyStore) *TokenVerifier {
	return &TokenVerifier{
		issuer:       Issuer(cfg.Issuer),
		keyset:       keyStore,
		requiredAlgs: []string{string(jose.RS256)}, // TODO: should lookup from config
	}
}

func ExternalTokenVerifiers(ctx context.Context, issuers ...Issuer) ([]*TokenVerifier, error) {
	result := make([]*TokenVerifier, 0, len(issuers))
	for _, issuer := range issuers {
		ti, err := ExternalTokenVerifier(ctx, issuer)
		if err != nil {
			return nil, err
		}
		result = append(result, ti)
	}
	return result, nil
}

func ExternalTokenVerifier(ctx context.Context, issuer Issuer) (*TokenVerifier, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	metadata, err := oauthclient.Discover(ctx, string(issuer), client)
	if err != nil {
		return nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}

	if metadata.Issuer != string(issuer) {
		return nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}

	algorithms := asymmetricAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %s", algorithms)
	}

	return &TokenVerifier{
		issuer:       issuer,
		keyset:       rp.NewRemoteKeySet(client, metadata.JwksURI),
		requiredAlgs: algorithms,
	}, nil
}

func asymmetricAlgorithms(advertised []string) []string {
	algorithms := make([]string, 0, len(advertised))
	for _, algorithm := range advertised {
		if strings.HasPrefix(algorithm, "RS") ||
			strings.HasPrefix(algorithm, "PS") ||
			strings.HasPrefix(algorithm, "ES") ||
			algorithm == "EdDSA" || // TODO: deprecated by RFC9864
			algorithm == "Ed25519" ||
			algorithm == "Ed448" {
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}
