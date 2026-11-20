package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/jwt"
)

func NewClientAuthTokenVerifier(ctx context.Context, httpClient *http.Client, issuers []jwt.Issuer, expectedAudience string, maxLifetime time.Duration) (*jwt.TokenVerifier, error) {
	opts := []jwt.TokenVerifierOption{
		jwt.WithHttpClient(httpClient),
		jwt.WithExpectedAudience(expectedAudience),
		jwt.WithMaxTokenLifetime(maxLifetime),
	}

	for _, issuer := range issuers {
		opts = append(opts, jwt.WithIssuer(issuer))
	}

	return jwt.NewTokenVerifier(ctx, opts...)
}

func (a *AuthorizationServer) authenticateClient(ctx context.Context, request *TokenExchangeRequest) (CallerIdentity, error) {
	finishStep := a.Metrics.StartTokenStep(ctx, "verify_client_assertion")
	claims, err := a.ClientAuthVerifier.Verify(ctx, request.ClientAssertion)
	finishStep(err)
	if err != nil {
		return CallerIdentity{}, errs.InvalidClient(err, "client assertion is invalid")
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "get_client")
	identity, err := a.resolveCallerIdentity(claims, request.ClientID)
	finishStep(err)
	return identity, err
}

// resolveCallerIdentity must only receive verified client assertion claims.
func (a *AuthorizationServer) resolveCallerIdentity(claims *jwt.AccessTokenClaims, requestedClientID ClientID) (CallerIdentity, error) {
	cfg, ok := a.GetClientAuthConfig(jwt.Issuer(claims.Issuer))
	if !ok {
		return CallerIdentity{}, errs.InvalidClient(nil, "client authentication configuration not found for issuer %q", claims.Issuer)
	}

	identity := CallerIdentity{}

	if cfg.Mode == ClientAuthImpersonation {
		if requestedClientID == "" {
			return CallerIdentity{}, errs.InvalidClient(nil, "client_id is required for issuer %q", claims.Issuer)
		}
		if err := requestedClientID.Validate(); err != nil {
			return CallerIdentity{}, errs.InvalidClient(err, "invalid client_id")
		}
		client, err := a.ClientStore.GetByID(requestedClientID)
		if errors.Is(err, ErrClientNotFound) {
			return CallerIdentity{}, errs.InvalidClient(err, "client authentication failed")
		}
		if err != nil {
			return CallerIdentity{}, err
		}
		identity.Client = client
		identity.Impersonator = &Impersonator{Issuer: claims.Issuer, Subject: claims.Subject}
		if !identity.AllowsImpersonation() {
			return CallerIdentity{}, errs.InvalidClient(nil, "client authentication failed")
		}
	} else {
		namespace, name, err := cfg.GetNamespaceAndName(claims)
		if err != nil {
			return CallerIdentity{}, errs.InvalidClient(err, "failed to extract namespace and name from client assertion claims")
		}
		client, err := a.ClientStore.Get(claims.Issuer, namespace, name)
		if err != nil {
			// TODO: can we handle this in generic error handling?
			if errors.Is(err, ErrClientNotFound) {
				return CallerIdentity{}, errs.InvalidClient(err, "client authentication failed")
			}
			return CallerIdentity{}, err
		}
		identity.Client = client
	}

	if !a.EnvironmentContainsIssuer(Name(identity.Client.Environment), jwt.Issuer(claims.Issuer)) {
		return CallerIdentity{}, errs.InvalidClient(nil, "client authentication failed")
	}
	return identity, nil
}

// CallerIdentity is the authenticated caller, not the subject of the token being exchanged.
type CallerIdentity struct {
	Client *Client
	// Impersonator is the verified impersonator acting as Client; nil for workloads.
	Impersonator *Impersonator
}

func (c CallerIdentity) AllowsImpersonation() bool {
	return c.Impersonator != nil && c.Impersonator.Subject != "" &&
		slices.Contains(c.Client.AuthorizationPolicy.AllowedImpersonators, *c.Impersonator)
}
