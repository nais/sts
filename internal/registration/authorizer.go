package registration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Authorizer struct {
	Registrators       []*Registrator
	ClientAuthVerifier oauth.MultiIssuerTokenVerifier
}

type Registrator struct {
	AuthIssuer   string
	AuthSubject  string
	RequiredAlgs []string
	KeySet       oidc.KeySet
}

func CreateAuthorizer(ctx context.Context, authServerCfg oauth.AuthorizationServerConfig, config ...*ClientRegistratorConfig) (*Authorizer, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	verifier, err := oauth.NewClientAuthTokenVerifier(ctx, authServerCfg.ClientAuthIssuers)
	if err != nil {
		return nil, err
	}
	r := make([]*Registrator, len(config))
	for i, cfg := range config {
		r[i] = &Registrator{
			AuthIssuer:   cfg.Issuer,
			AuthSubject:  cfg.Subject,
			RequiredAlgs: cfg.RequiredAlgs,
			KeySet:       rp.NewRemoteKeySet(httpClient, cfg.ClientJwksUri),
		}
	}
	return &Authorizer{
		Registrators:       r,
		ClientAuthVerifier: verifier,
	}, nil
}

func (a *Authorizer) Authorize(r *http.Request) (*Registrator, error) {
	token, ok := bearerToken(r)
	if !ok {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("missing bearer token")
	}
	claims, err :=  a.ClientAuthVerifier.Verify(r.Context(), token, func(claims *oauth.AccessTokenClaims) error {
		// TODO: verify extra claims for authorized client registrators
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify client auth token: %w", err)
	}

	return a.GetRegistrator(claims)
}

func (a *Authorizer) GetRegistrator(authTokenClaims *oauth.AccessTokenClaims) (*Registrator, error) {
	var registrator *Registrator
	for _, client := range a.Registrators {
		if authTokenClaims.Issuer == client.AuthIssuer && authTokenClaims.Subject == client.AuthSubject {
			registrator = client
			break
		}
	}
	if registrator == nil {
		return nil, fmt.Errorf("could not find registrator for issuer %q and subject %q", authTokenClaims.Issuer, authTokenClaims.Subject)
	}
	return registrator, nil
}

func (r *Registrator) VerifySoftwareStatement(ctx context.Context, softwareStatementString string) (*SoftwareStatement, error) {
	ss := new(SoftwareStatement)
	payload, err := oidc.ParseToken(softwareStatementString, ss)
	if err != nil {
		return nil, err
	}
	if err = oidc.CheckSignature(ctx, softwareStatementString, payload, ss, r.RequiredAlgs, r.KeySet); err != nil {
		return nil, err
	}
	return ss, nil
}

func bearerToken(r *http.Request) (token string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}

	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	token = auth[len(prefix):]
	if len(token) == 0 {
		return "", false
	}
	return token, true
}
