package oauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	oauthclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenVerifier struct {
	issuer       TokenIssuer
	keyset       oidc.KeySet
	requiredAlgs []string
}

func NewTokenVerifier(issuer TokenIssuer, keyset oidc.KeySet, requiredAlgs ...string) (*TokenVerifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
	}
	if keyset == nil {
		return nil, fmt.Errorf("key set must not be nil")
	}
	if len(requiredAlgs) == 0 {
		return nil, fmt.Errorf("required algorithms must not be empty")
	}
	return &TokenVerifier{
		issuer:       issuer,
		keyset:       keyset,
		requiredAlgs: requiredAlgs,
	}, nil
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
			return nil, fmt.Errorf("nbf (%v) is after the accepted time (%v)", claims.NotBefore.AsTime(), nowWithOffset)
		}
	}
	return claims, nil
}

type MultiIssuerTokenVerifier map[TokenIssuer]*TokenVerifier

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

	verifier, ok := v[TokenIssuer(claims.Issuer)]
	if !ok {
		return nil, fmt.Errorf("issuer %q is not trusted", claims.Issuer)
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

func NewTokenExchangeTokenVerifier(ctx context.Context, httpClient *http.Client, cfg AuthorizationServerConfig, keyStore KeyStore) (MultiIssuerTokenVerifier, error) {
	subjectTokenVerifiers, err := ExternalTokenVerifiers(ctx, httpClient, cfg.SubjectTokenIssuers.Issuers()...)
	if err != nil {
		return nil, fmt.Errorf("resolving subject token verifiers: %w", err)
	}
	internalTokenVerifier, err := InternalTokenVerifier(cfg, keyStore)
	if err != nil {
		return nil, fmt.Errorf("creating internal token verifier: %w", err)
	}
	return NewMultiIssuerTokenVerifier(append(
		subjectTokenVerifiers,
		internalTokenVerifier,
	)...)
}

func InternalTokenVerifier(cfg AuthorizationServerConfig, keyStore KeyStore) (*TokenVerifier, error) {
	return NewTokenVerifier(TokenIssuer(cfg.Issuer),
		keyStore,
		string(InternalSigningAlgorithm),
	)
}

func ExternalTokenVerifiers(ctx context.Context, httpClient *http.Client, issuers ...TokenIssuer) ([]*TokenVerifier, error) {
	result := make([]*TokenVerifier, 0, len(issuers))
	for _, issuer := range issuers {
		ti, err := ExternalTokenVerifier(ctx, httpClient, issuer)
		if err != nil {
			return nil, err
		}
		result = append(result, ti)
	}
	return result, nil
}

func ExternalTokenVerifier(ctx context.Context, httpClient *http.Client, issuer TokenIssuer) (*TokenVerifier, error) {
	return externalTokenVerifier(ctx, httpClient, issuer, nil)
}

func externalTokenVerifier(ctx context.Context, httpClient *http.Client, issuer TokenIssuer, allowedAlgorithms []string) (*TokenVerifier, error) {
	metadata, err := oauthclient.Discover(ctx, string(issuer), httpClient)
	if err != nil {
		return nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}

	if metadata.Issuer != string(issuer) {
		return nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}

	algorithms := allowedAlgorithms
	if algorithms == nil {
		algorithms = asymmetricAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	}
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %v", metadata.IDTokenSigningAlgValuesSupported)
	}

	return NewTokenVerifier(issuer, rp.NewRemoteKeySet(httpClient, metadata.JwksURI), algorithms...)
}

func asymmetricAlgorithms(advertised []string) []string {
	algorithms := make([]string, 0, len(advertised))
	for _, algorithm := range advertised {
		if isSupportedSigningAlgorithm(algorithm) {
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}
