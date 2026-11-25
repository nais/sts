package jwt

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"time"

	internalhttp "github.com/nais/sts/internal/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenVerifier struct {
	issuers    map[Issuer]issuerConfig
	httpClient *http.Client
}

type issuerConfig struct {
	issuer           Issuer
	keyset           oidc.KeySet
	requiredAlgs     []string
	expectedAudience string
	maxTokenLifetime time.Duration
}

func WithIssuer(issuer Issuer, opts ...IssuerOption) TokenVerifierOption {
	return func(t *TokenVerifier) {
		cfg := issuerConfig{issuer: issuer}
		for _, opt := range opts {
			opt(&cfg)
		}
		t.issuers[issuer] = cfg
	}
}

// WithKeySet uses keySet instead of discovering the issuer's remote key set.
func WithKeySet(keySet oidc.KeySet, requiredAlgs ...string) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.keyset = keySet
		cfg.requiredAlgs = requiredAlgs
	}
}

type TokenVerifierOption func(*TokenVerifier)

func WithHttpClient(client *http.Client) TokenVerifierOption {
	return func(t *TokenVerifier) {
		t.httpClient = client
	}
}

func WithIssuersFrom(other *TokenVerifier) TokenVerifierOption {
	return func(t *TokenVerifier) {
		maps.Copy(t.issuers, other.issuers)
	}
}

type IssuerOption func(*issuerConfig)

func WithExpectedAudience(audience string) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.expectedAudience = audience
	}
}

func WithMaxTokenLifetime(maxLifetime time.Duration) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.maxTokenLifetime = maxLifetime
	}
}

func NewTokenVerifier(ctx context.Context, opts ...TokenVerifierOption) (*TokenVerifier, error) {
	t := &TokenVerifier{
		issuers:    map[Issuer]issuerConfig{},
		httpClient: internalhttp.NewClient(),
	}
	for _, opt := range opts {
		opt(t)
	}
	if len(t.issuers) == 0 {
		return nil, fmt.Errorf("no issuers configured")
	}

	for _, cfg := range t.issuers {
		if cfg.keyset == nil {
			var err error
			cfg.keyset, cfg.requiredAlgs, err = discoverRemoteKeySet(ctx, cfg.issuer, t.httpClient)
			if err != nil {
				return nil, fmt.Errorf("resolving key set for issuer %q: %w", cfg.issuer, err)
			}
		}
		t.issuers[cfg.issuer] = cfg
	}

	return t, nil
}

type VerifyFn func(claims *AccessTokenClaims) error

func (t *TokenVerifier) Verify(ctx context.Context, rawToken string, verifyFn ...VerifyFn) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}

	cfg, ok := t.issuers[Issuer(claims.Issuer)]
	if !ok {
		return nil, fmt.Errorf("issuer %q is not trusted", claims.Issuer)
	}

	if err := oidc.CheckSignature(ctx, rawToken, payload, claims, cfg.requiredAlgs, cfg.keyset); err != nil {
		return nil, fmt.Errorf("issuer %q: %w", claims.Issuer, err)
	}

	verifiedClaims, err := t.verifyClaims(cfg, claims)
	if err != nil {
		return nil, fmt.Errorf("issuer %q: %w", claims.Issuer, err)
	}

	for _, fn := range verifyFn {
		if err := fn(verifiedClaims); err != nil {
			return nil, fmt.Errorf("issuer %q: %w", claims.Issuer, err)
		}
	}

	return verifiedClaims, nil
}

func (t *TokenVerifier) verifyClaims(cfg issuerConfig, claims *AccessTokenClaims) (*AccessTokenClaims, error) {
	const SkewTime = time.Minute

	if claims.Issuer != string(cfg.issuer) {
		return nil, oidc.ErrIssuerInvalid
	}
	if err := oidc.CheckExpiration(claims, SkewTime); err != nil {
		return nil, err
	}
	if err := oidc.CheckIssuedAt(claims, cfg.maxTokenLifetime, SkewTime); err != nil {
		return nil, err
	}
	if !claims.Expiration.AsTime().After(claims.IssuedAt.AsTime()) {
		return nil, fmt.Errorf("expiration (%v) must be after issued-at (%v)", claims.Expiration.AsTime(), claims.IssuedAt.AsTime())
	}
	if !claims.NotBefore.AsTime().IsZero() {
		nowWithOffset := time.Now().Add(SkewTime).Round(time.Second)
		if claims.NotBefore.AsTime().After(nowWithOffset) {
			return nil, fmt.Errorf("nbf (%v) is after the accepted time (%v)", claims.NotBefore.AsTime(), nowWithOffset)
		}
	}
	if cfg.expectedAudience != "" {
		if len(claims.Audience) != 1 || claims.Audience[0] != cfg.expectedAudience {
			return nil, fmt.Errorf("audience %q is invalid, expected %q", claims.Audience, cfg.expectedAudience)
		}
	}

	return claims, nil
}
