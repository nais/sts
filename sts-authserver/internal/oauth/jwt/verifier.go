package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/sts/internal/jwa"
	oauthclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenVerifier struct {
	verifiers map[string]verifier
}

type verifier struct {
	issuer         string
	keyset         oidc.KeySet
	requiredAlgs   []string
	claimsVerifier func(claims *oidc.AccessTokenClaims) error
}

type tokenVerifierConfig struct {
	issuers        []verifier
	httpClient     *http.Client
	claimsVerifier func(claims *oidc.AccessTokenClaims) error
}

type TokenVerifierOption func(*tokenVerifierConfig)

func WithHttpClient(client *http.Client) TokenVerifierOption {
	return func(cfg *tokenVerifierConfig) {
		cfg.httpClient = client
	}
}

func WithIssuer(issuer string) TokenVerifierOption {
	return func(cfg *tokenVerifierConfig) {
		cfg.issuers = append(cfg.issuers, verifier{
			issuer: issuer,
		})
	}
}

func WithIssuerAndKeySet(issuer string, keySet oidc.KeySet, requiredAlgs ...string) TokenVerifierOption {
	return func(cfg *tokenVerifierConfig) {
		cfg.issuers = append(cfg.issuers, verifier{
			issuer:       issuer,
			keyset:       keySet,
			requiredAlgs: requiredAlgs,
		})
	}
}

func WithClaimsVerifier(claimsVerifier func(claims *oidc.AccessTokenClaims) error) TokenVerifierOption {
	return func(cfg *tokenVerifierConfig) {
		cfg.claimsVerifier = claimsVerifier
	}
}

func NewTokenVerifier(ctx context.Context, opts ...TokenVerifierOption) (*TokenVerifier, error) {
	cfg := &tokenVerifierConfig{
		issuers:    []verifier{},
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if len(cfg.issuers) == 0 {
		return nil, fmt.Errorf("no issuers configured")
	}

	verifiers := make(map[string]verifier)
	for _, issuer := range cfg.issuers {
		if issuer.keyset == nil {
			var err error
			issuer.keyset, issuer.requiredAlgs, err = discoverRemoteKeySet(ctx, issuer.issuer, cfg.httpClient)
			if err != nil {
				return nil, fmt.Errorf("resolving key set for issuer %q: %w", issuer.issuer, err)
			}
		}

		issuer.claimsVerifier = cfg.claimsVerifier
		verifiers[issuer.issuer] = issuer
	}

	return &TokenVerifier{
		verifiers: verifiers,
	}, nil
}

func (m TokenVerifier) Verify(ctx context.Context, rawToken string) (*oidc.AccessTokenClaims, error) {
	claims := new(oidc.AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}

	v, ok := m.verifiers[claims.Issuer]
	if !ok {
		return nil, fmt.Errorf("issuer %q is not trusted", claims.Issuer)
	}

	verifiedClaims, err := v.Verify(ctx, rawToken, payload, claims)
	if err != nil {
		return nil, err
	}

	return verifiedClaims, nil
}

func (v verifier) Verify(ctx context.Context, rawToken string, payload []byte, claims *oidc.AccessTokenClaims) (*oidc.AccessTokenClaims, error) {
	const SkewTime = time.Minute

	if claims.Issuer != v.issuer {
		return nil, oidc.ErrIssuerInvalid
	}
	if err := oidc.CheckSignature(ctx, rawToken, payload, claims, v.requiredAlgs, v.keyset); err != nil {
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
			return nil, fmt.Errorf("nbf (%v) is after the accepted time (%v)", claims.NotBefore.AsTime(), nowWithOffset)
		}
	}
	if v.claimsVerifier != nil {
		err := v.claimsVerifier(claims)
		if err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func discoverRemoteKeySet(ctx context.Context, issuer string, client *http.Client) (oidc.KeySet, []string, error) {
	metadata, err := oauthclient.Discover(ctx, issuer, client)
	if err != nil {
		return nil, nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}

	if metadata.Issuer != issuer {
		return nil, nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}

	algorithms := jwa.FilterSupportedAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %v", metadata.IDTokenSigningAlgValuesSupported)
	}

	return rp.NewRemoteKeySet(client, metadata.JwksURI), algorithms, nil
}
