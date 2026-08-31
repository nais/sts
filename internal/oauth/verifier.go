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

func NewTokenVerifier(ctx context.Context, issuers ...Issuer) (*TokenVerifier, error) {
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
	return ret, nil
}

func (t *TokenVerifier) Verify(ctx context.Context, rawToken string) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}
	v, ok := t.verifiers[Issuer(claims.Issuer)]
	if !ok {
		return nil, fmt.Errorf("issuer %q not supported", claims.Issuer)
	}
	return v.verify(ctx, rawToken, payload, claims)
}

func newVerifier(ctx context.Context, issuer string, client *http.Client) (*verifier, error) {
	metadata, err := oauthclient.Discover(ctx, issuer, client)
	if err != nil {
		return nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}
	if metadata.Issuer != issuer {
		return nil, fmt.Errorf("issuer %q does not match issuer: %q in wellknown metadata", issuer, metadata.Issuer)
	}
	algorithms := asymmetricAlgorithms(metadata.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms")
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
	nowWithOffset := time.Now().Add(SkewTime).Round(time.Second)
	if !claims.NotBefore.AsTime().IsZero() && claims.NotBefore.AsTime().After(nowWithOffset) {
		return nil, fmt.Errorf("nbf not valid: (nbf: %v, now with offset: %v)", claims.NotBefore, nowWithOffset)
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
