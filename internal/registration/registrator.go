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

type Registrators struct {
	byIdentity         map[registratorIdentity]*Registrator
	clientAuthVerifier oauth.MultiIssuerTokenVerifier
	expectedAudience   string
	maxTokenLifetime   time.Duration
}

type registratorIdentity struct {
	issuer  string
	subject string
}

type Registrator struct {
	AuthIssuer   string
	AuthSubject  string
	RequiredAlgs []string
	KeySet       oidc.KeySet
}

func NewRegistrators(ctx context.Context, httpClient *http.Client, authServerCfg oauth.AuthorizationServerConfig, config ...*ClientRegistratorConfig) (*Registrators, error) {
	verifier, err := oauth.NewClientAuthTokenVerifier(ctx, httpClient, authServerCfg.ClientAuthIssuers, authServerCfg.ClientAuthSigningAlgorithms)
	if err != nil {
		return nil, err
	}
	registrators := make(map[registratorIdentity]*Registrator, len(config))
	for _, cfg := range config {
		registrators[registratorIdentity{issuer: cfg.Issuer, subject: cfg.Subject}] = &Registrator{
			AuthIssuer:   cfg.Issuer,
			AuthSubject:  cfg.Subject,
			RequiredAlgs: cfg.RequiredAlgs,
			KeySet:       rp.NewRemoteKeySet(httpClient, cfg.ClientJwksUri),
		}
	}
	return &Registrators{
		byIdentity:         registrators,
		clientAuthVerifier: verifier,
		expectedAudience:   authServerCfg.ExpectedAudience,
		maxTokenLifetime:   authServerCfg.MaxClientAuthTokenLifetime,
	}, nil
}

func (r *Registrators) Authenticate(request *http.Request) (*Registrator, error) {
	token, ok := bearerToken(request)
	if !ok {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("missing bearer token")
	}
	claims, err := r.clientAuthVerifier.Verify(request.Context(), token, func(claims *oauth.AccessTokenClaims) error {
		return oauth.ValidateClientAuthClaims(claims, r.expectedAudience, r.maxTokenLifetime)
	})
	if err != nil {
		return nil, fmt.Errorf("verify client auth token: %w", err)
	}

	registrator := r.byIdentity[registratorIdentity{issuer: claims.Issuer, subject: claims.Subject}]
	if registrator == nil {
		return nil, fmt.Errorf("could not find registrator for issuer %q and subject %q", claims.Issuer, claims.Subject)
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
	if err := ss.validate(); err != nil {
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
