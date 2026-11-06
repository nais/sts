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
	issuers        map[Issuer]issuerConfig
	httpClient     *http.Client
	claimsVerifier func(claims *AccessTokenClaims) error
}

type issuerConfig struct {
	issuer       Issuer
	keyset       oidc.KeySet
	requiredAlgs []string
}

type TokenVerifierOption func(*TokenVerifier)

func WithHttpClient(client *http.Client) TokenVerifierOption {
	return func(t *TokenVerifier) {
		t.httpClient = client
	}
}

func WithIssuer(issuer Issuer) TokenVerifierOption {
	return func(t *TokenVerifier) {
		t.issuers[issuer] = issuerConfig{
			issuer: issuer,
		}
	}
}

func WithIssuerAndKeySet(issuer Issuer, keySet oidc.KeySet, requiredAlgs ...string) TokenVerifierOption {
	return func(t *TokenVerifier) {
		t.issuers[issuer] = issuerConfig{
			issuer:       issuer,
			keyset:       keySet,
			requiredAlgs: requiredAlgs,
		}
	}
}

func WithClaimsVerifier(claimsVerifier func(claims *AccessTokenClaims) error) TokenVerifierOption {
	return func(t *TokenVerifier) {
		t.claimsVerifier = claimsVerifier
	}
}

func NewTokenVerifier(ctx context.Context, opts ...TokenVerifierOption) (*TokenVerifier, error) {
	t := &TokenVerifier{
		issuers: map[Issuer]issuerConfig{},
		// TODO: consider extracting sts.httpClient
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf("redirect to %q is not allowed", req.URL)
			},
		},
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
		return nil, err
	}

	verifiedClaims, err := t.verifyClaims(cfg, claims)
	if err != nil {
		return nil, err
	}

	if t.claimsVerifier != nil {
		err := t.claimsVerifier(claims)
		if err != nil {
			return nil, err
		}
	}

	for _, fn := range verifyFn {
		if err := fn(verifiedClaims); err != nil {
			return nil, err
		}
	}

	return verifiedClaims, nil
}

func (t *TokenVerifier) verifyClaims(v issuerConfig, claims *AccessTokenClaims) (*AccessTokenClaims, error) {
	const SkewTime = time.Minute

	if claims.Issuer != string(v.issuer) {
		return nil, oidc.ErrIssuerInvalid
	}
	if err := oidc.CheckExpiration(claims, SkewTime); err != nil {
		return nil, err
	}
	if err := oidc.CheckIssuedAt(claims, 0, SkewTime); err != nil {
		return nil, err
	}
	if !claims.Expiration.AsTime().After(claims.IssuedAt.AsTime()) {
		return nil, fmt.Errorf("expiration (%v) must be after issued-at (%v)", claims.Expiration.AsTime(), claims.IssuedAt.AsTime())
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
	return claims, nil
}

func discoverRemoteKeySet(ctx context.Context, issuer Issuer, client *http.Client) (oidc.KeySet, []string, error) {
	metadata, err := oauthclient.Discover(ctx, string(issuer), client)
	if err != nil {
		return nil, nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}

	if metadata.Issuer != string(issuer) {
		return nil, nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}

	algorithms := jwa.FilterSupportedAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %v", metadata.IDTokenSigningAlgValuesSupported)
	}

	return rp.NewRemoteKeySet(client, metadata.JwksURI), algorithms, nil
}
