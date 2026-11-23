package registration

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"

	"github.com/nais/sts/internal/http"
	"github.com/nais/sts/internal/jwt"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Registrators struct {
	environments       []oauth.Name
	byIdentity         map[registratorIdentity]*Registrator
	clientAuthVerifier *jwt.TokenVerifier
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

func NewRegistrators(ctx context.Context, httpClient *nethttp.Client, authServerCfg oauth.AuthorizationServerConfig) (*Registrators, error) {
	if err := authServerCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid authorization server configuration: %w", err)
	}
	environments := authServerCfg.Environments
	registrators := make(map[registratorIdentity]*Registrator, len(environments))
	names := make([]oauth.Name, len(environments))

	issuers := make(oauth.ClientAuthIssuers)
	for i, env := range environments {
		names[i] = env.Name
		cfg, ok := authServerCfg.ClientAuthIssuers[env.Registrator.IssuerRef]
		if !ok {
			return nil, fmt.Errorf("could not find client auth issuer for %q", env.Registrator.IssuerRef)
		}
		if cfg.Mode == oauth.ClientAuthWorkload {
			issuers[string(cfg.Issuer)] = cfg
			issuer := string(cfg.Issuer)
			identity := registratorIdentity{issuer: issuer, subject: env.Registrator.Subject}
			registrators[identity] = &Registrator{
				Environment:  env.Name,
				AuthIssuer:   issuer,
				AuthSubject:  env.Registrator.Subject,
				RequiredAlgs: []string{env.Registrator.SigningAlg},
				KeySet:       rp.NewRemoteKeySet(httpClient, env.Registrator.RegistratorJwksUri),
			}
		}
	}
	verifier, err := oauth.NewClientAuthTokenVerifier(ctx, httpClient, issuers)
	if err != nil {
		return nil, err
	}
	return &Registrators{
		environments:       names,
		byIdentity:         registrators,
		clientAuthVerifier: verifier,
	}, nil
}

func (r *Registrators) Authenticate(request *nethttp.Request) (*Registrator, error) {
	token, ok := http.BearerToken(request)
	if !ok {
		return nil, errors.New("missing bearer token")
	}
	claims, err := r.clientAuthVerifier.Verify(request.Context(), token)
	if err != nil {
		return nil, err
	}

	return r.getRegistrator(claims.Issuer, claims.Subject)
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

func (r *Registrators) getRegistrator(issuer, subject string) (*Registrator, error) {
	registrator := r.byIdentity[registratorIdentity{issuer: issuer, subject: subject}]
	if registrator == nil {
		return nil, fmt.Errorf("could not find registrator for issuer %q and subject %q", issuer, subject)
	}
	return registrator, nil
}
