package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TODO: caching of jwks, rewrite
type TokenVerifier struct {
	httpClient *http.Client
}

func NewTokenVerifier() *TokenVerifier {
	return &TokenVerifier{httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (v *TokenVerifier) Verify(ctx context.Context, raw, issuer string) (*AccessTokenClaims, error) {
	claims := new(AccessTokenClaims)
	payload, err := oidc.ParseToken(raw, claims)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != issuer {
		return nil, oidc.ErrIssuerInvalid
	}

	configuration, err := client.Discover(ctx, issuer, v.httpClient)
	if err != nil {
		return nil, err
	}
	algorithms := asymmetricAlgorithms(configuration.IDTokenSigningAlgValuesSupported)
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms")
	}
	if err := oidc.CheckSignature(ctx, raw, payload, claims, algorithms, rp.NewRemoteKeySet(v.httpClient, configuration.JwksURI)); err != nil {
		return nil, err
	}
	if err := oidc.CheckExpiration(claims, 0); err != nil {
		return nil, err
	}
	if err := oidc.CheckIssuedAt(claims, 0, 0); err != nil {
		return nil, err
	}
	if err := oidc.CheckSubject(claims); err != nil {
		return nil, err
	}
	if !claims.NotBefore.AsTime().IsZero() && time.Now().Before(claims.NotBefore.AsTime()) {
		return nil, fmt.Errorf("token is not valid yet")
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
