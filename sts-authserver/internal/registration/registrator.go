package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Registrators struct {
	environments       []oauth.Name
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
	Environment  oauth.Name
	AuthIssuer   string
	AuthSubject  string
	RequiredAlgs []string
	KeySet       oidc.KeySet
}

func NewRegistrators(ctx context.Context, httpClient *http.Client, authServerCfg oauth.AuthorizationServerConfig) (*Registrators, error) {
	environments := authServerCfg.Environments
	verifier, err := oauth.NewClientAuthTokenVerifier(ctx, httpClient, environments.ClientAuthIssuers(), authServerCfg.ClientAuthSigningAlgorithms)
	if err != nil {
		return nil, err
	}
	registrators := make(map[registratorIdentity]*Registrator, len(environments))
	names := make([]oauth.Name, len(environments))
	for i, env := range environments {
		names[i] = env.Name
		issuer := string(env.ClientAuthIssuer)
		registrators[registratorIdentity{issuer: issuer, subject: env.Registrator.Subject}] = &Registrator{
			Environment:  env.Name,
			AuthIssuer:   issuer,
			AuthSubject:  env.Registrator.Subject,
			RequiredAlgs: []string{env.Registrator.SigningAlg},
			KeySet:       rp.NewRemoteKeySet(httpClient, env.Registrator.RegistratorJwksUri),
		}
	}
	return &Registrators{
		environments:       names,
		byIdentity:         registrators,
		clientAuthVerifier: verifier,
		expectedAudience:   authServerCfg.ExpectedAudience,
		maxTokenLifetime:   authServerCfg.MaxClientAuthTokenLifetime,
	}, nil
}

func (r *Registrators) Authenticate(request *http.Request) (*Registrator, error) {
	token, ok := bearerToken(request)
	if !ok {
		return nil, errors.New("missing bearer token")
	}
	claims, err := r.clientAuthVerifier.Verify(request.Context(), token, func(claims *oauth.AccessTokenClaims) error {
		return oauth.ValidateClientAuthClaims(claims, r.expectedAudience, r.maxTokenLifetime)
	})
	if err != nil {
		return nil, err
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
	if err := oidc.CheckSignature(ctx, softwareStatementString, payload, ss, r.RequiredAlgs, r.KeySet); err != nil {
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
