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

type TokenVerifier struct {
	issuer       string
	jwksURI      string
	client       *http.Client
	keyset       oidc.KeySet
	requiredAlgs []string
}

func NewTokenVerifier(ctx context.Context, issuer string) (*TokenVerifier, error) {
	client := &http.Client{Timeout: 5 * time.Second}
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
	return &TokenVerifier{
		issuer: issuer,
		client: client,
		keyset: keyset,
	}, nil
}

func (t *TokenVerifier) Verify(ctx context.Context, rawToken string) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(rawToken, claims)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != t.issuer {
		return nil, oidc.ErrIssuerInvalid
	}
	if err := oidc.CheckSignature(ctx, rawToken, payload, claims, t.requiredAlgs, t.keyset); err != nil {
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
