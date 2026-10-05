package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/nais/sts/internal/errs"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthorizationServer struct {
	ClientAuthVerifier    MultiIssuerTokenVerifier
	ClientStore           ClientStore
	KeyStore              KeyStore
	TokenExchangeVerifier MultiIssuerTokenVerifier
	Metrics               *stsmetrics.Metrics
	AuthorizationServerConfig
}

func NewAuthorizationServer(ctx context.Context, httpClient *http.Client, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore, metrics *stsmetrics.Metrics) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewClientAuthTokenVerifier(ctx, httpClient, cfg.ClientAuthIssuers, cfg.ClientAuthSigningAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}

	var tokenExchangeVerifier MultiIssuerTokenVerifier
	if len(cfg.SubjectTokenIssuers) > 0 {
		tokenExchangeVerifier, err = NewTokenExchangeTokenVerifier(ctx, httpClient, cfg, keyStore)
		if err != nil {
			return nil, fmt.Errorf("creating token exchange verifier: %w", err)
		}
	}

	return &AuthorizationServer{
		ClientAuthVerifier:        clientAuthVerifier,
		ClientStore:               clientStore,
		KeyStore:                  keyStore,
		TokenExchangeVerifier:     tokenExchangeVerifier,
		Metrics:                   metrics,
		AuthorizationServerConfig: cfg,
	}, nil
}

type AuthorizationResult struct {
	Target             Target
	GrantType          oidc.GrantType
	SubjectTokenClaims *AccessTokenClaims
	Client             *Client
	Roles              Roles
}

func (a *AuthorizationServer) AuthorizeRequest(ctx context.Context, request TokenRequest) (*AuthorizationResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "verify_client_assertion")
	clientAuthClaims, err := a.ClientAuthVerifier.Verify(ctx, request.GetClientAuthCredentials().ClientAssertion, a.verifyClientAuthClaims)
	finishStep(err)
	if err != nil {
		return nil, errs.InvalidClient(err, "client assertion is invalid")
	}

	target, err := request.Target()
	if err != nil {
		return nil, err
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "get_client")
	client, err := a.ClientStore.Get(ctx, clientAuthClaims)
	finishStep(err)
	if errors.Is(err, ErrClientNotFound) {
		return nil, errs.InvalidClient(err, "client authentication failed")
	}
	if err != nil {
		return nil, err
	}

	var claims *AccessTokenClaims
	if request.GrantType() == oidc.GrantTypeTokenExchange {
		te, ok := request.(*TokenExchangeRequest)
		if !ok {
			return nil, fmt.Errorf("request is %T, want *TokenExchangeRequest", request)
		}
		finishStep = a.Metrics.StartTokenStep(ctx, "verify_subject_token")
		claims, err = a.TokenExchangeVerifier.Verify(ctx, te.SubjectToken, func(claims *AccessTokenClaims) error {
			return a.verifySTSIssuedSubjectTokenClaims(claims, client.ID)
		})
		finishStep(err)
		if err != nil {
			return nil, errs.InvalidRequest(err, "subject token is invalid")
		}
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "authorize_target")
	roles, err := a.ClientStore.AuthorizeTarget(ctx, ClientID(client.ID), target)
	finishStep(err)
	if errors.Is(err, ErrTargetUnauthorized) {
		return nil, errs.InvalidTarget(err, "client is not authorized for target %q", target.GetValue())
	}
	if err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		Target:             target,
		SubjectTokenClaims: claims,
		Client:             client,
		Roles:              roles,
		GrantType:          request.GrantType(),
	}, nil
}

func (a *AuthorizationServer) GrantHandler(ctx context.Context, request TokenRequest) (*AccessTokenResponse, error) {
	finishGrant := a.Metrics.StartTokenGrant(ctx, request.GrantType())
	var err error
	defer func() { finishGrant(err) }()

	result, err := a.AuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	response, err := a.CreateTokenResponse(ctx, result)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (a *AuthorizationServer) CreateTokenResponse(ctx context.Context, result *AuthorizationResult) (*AccessTokenResponse, error) {
	accessToken, err := CreateAccessToken(a.Issuer, a.SubjectTokenIssuers, a.TokenExpiry, result)
	if err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "get_signer")
	signer, err := a.KeyStore.Signer()
	finishStep(err)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}
	finishStep = a.Metrics.StartTokenStep(ctx, "sign_token")
	signed, err := accessToken.Sign(signer)
	finishStep(err)
	if err != nil {
		return nil, err
	}
	ret := &AccessTokenResponse{
		AccessToken: signed,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(accessToken.ExpiresIn().Seconds()),
	}

	if result.GrantType == oidc.GrantTypeTokenExchange {
		ret.IssuedTokenType = oidc.AccessTokenType
	}
	return ret, nil
}

func (a *AuthorizationServer) verifyClientAuthClaims(claims *AccessTokenClaims) error {
	return ValidateClientAuthClaims(claims, a.ExpectedAudience, a.MaxClientAuthTokenLifetime)
}

func (a *AuthorizationServer) verifySTSIssuedSubjectTokenClaims(claims *AccessTokenClaims, clientID string) error {
	if claims.Issuer != string(a.Issuer) {
		return nil
	}

	rawGrantType, ok := claims.Claims["urn:nais:grant_type"]
	if !ok {
		return errors.New("grant_type claim is missing")
	}

	var grantType oidc.GrantType
	if err := json.Unmarshal(rawGrantType, &grantType); err != nil {
		return errors.New("grant_type claim must be a string")
	}

	if grantType != oidc.GrantTypeTokenExchange {
		return fmt.Errorf("grant_type claim is invalid: got %q, want %q", grantType, oidc.GrantTypeTokenExchange)
	}

	if !slices.Contains(claims.Audience, clientID) {
		return fmt.Errorf("subject token audience %q does not contain client_id %q", claims.Audience, clientID)
	}
	return nil
}

func ValidateClientAuthClaims(claims *AccessTokenClaims, expectedAudience string, maxLifetime time.Duration) error {
	if len(claims.Audience) != 1 || claims.Audience[0] != expectedAudience {
		return fmt.Errorf("audience %q is invalid, expected %q", claims.Audience, expectedAudience)
	}
	issuedAt := claims.IssuedAt.AsTime()
	if issuedAt.IsZero() {
		return errors.New("issued at claim is missing")
	}
	expiration := claims.Expiration.AsTime()
	if expiration.IsZero() {
		return errors.New("expiration claim is missing")
	}
	if !expiration.After(issuedAt) {
		return errors.New("expiration must be after issued-at")
	}
	if expiration.Sub(issuedAt) > maxLifetime+time.Minute {
		return fmt.Errorf("token lifetime %s exceeds maximum %s", expiration.Sub(issuedAt), maxLifetime)
	}
	return nil
}
