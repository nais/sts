package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	oauthclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const SkewTime = time.Minute

type Issuer string

type TokenVerifier struct {
	verifiers map[Issuer]*verifier
}

type verifier struct {
	issuer       string
	keyset       oidc.KeySet
	requiredAlgs []string
}

type internalIssuer struct {
	Issuer       string
	Keyset       oidc.KeySet
	RequiredAlgs []string
}

func NewTokenVerifier(ctx context.Context, i *internalIssuer, issuers ...Issuer) (*TokenVerifier, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	ret := &TokenVerifier{
		verifiers: make(map[Issuer]*verifier),
	}
	for _, issuer := range issuers {
		v, err := newVerifier(ctx, string(issuer), client)
		if err != nil {
			return nil, err
		}
		ret.verifiers[issuer] = v
	}
	if i != nil {
		ret.verifiers[Issuer(i.Issuer)] = &verifier{
			issuer:       i.Issuer,
			keyset:       i.Keyset,
			requiredAlgs: i.RequiredAlgs,
		}
	}
	return ret, nil
}

type VerifyFn func(claims *AccessTokenClaims) error

func (t *TokenVerifier) Verify(ctx context.Context, rawToken string, fns ...VerifyFn) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}
	v, ok := t.verifiers[Issuer(claims.Issuer)]
	if !ok {
		return nil, fmt.Errorf("issuer %q not supported", claims.Issuer)
	}

	verifiedClaims, err := v.verify(ctx, rawToken, payload, claims)
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

func newVerifier(ctx context.Context, issuer string, client *http.Client) (*verifier, error) {
	metadata, err := oauthclient.Discover(ctx, issuer, client)
	if err != nil {
		return nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}
	if metadata.Issuer != issuer {
		return nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}
	algorithms := asymmetricAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %s", algorithms)
	}
	keyset := rp.NewRemoteKeySet(client, metadata.JwksURI)
	return &verifier{
		issuer:       issuer,
		keyset:       keyset,
		requiredAlgs: algorithms,
	}, nil
}

func (v *verifier) verify(ctx context.Context, rawToken string, payload []byte, claims *AccessTokenClaims) (*AccessTokenClaims, error) {
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
			return nil, fmt.Errorf("nbf is in the future: (nbf: %v, now with offset: %v)", claims.NotBefore, nowWithOffset)
		}
	}
	return claims, nil
}

func asymmetricAlgorithms(advertised []string) []string {
	algorithms := make([]string, 0, len(advertised))
	for _, algorithm := range advertised {
		if strings.HasPrefix(algorithm, "RS") || strings.HasPrefix(algorithm, "PS") || strings.HasPrefix(algorithm, "ES") || algorithm == "EdDSA" {
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}
