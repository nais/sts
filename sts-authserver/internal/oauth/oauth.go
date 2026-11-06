package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/jwt"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthorizationServer struct {
	ClientAuthVerifier    *jwt.TokenVerifier
	ClientStore           ClientStore
	KeyStore              KeyStore
	TokenExchangeVerifier *jwt.TokenVerifier
	Metrics               *stsmetrics.Metrics
	AuthorizationServerConfig
}

func NewAuthorizationServer(ctx context.Context, httpClient *http.Client, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore, metrics *stsmetrics.Metrics) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewClientAuthTokenVerifier(ctx, httpClient, cfg.Environments.ClientAuthIssuers(), cfg.ExpectedAudience, cfg.MaxClientAuthTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}

	opts := []jwt.TokenVerifierOption{
		jwt.WithHttpClient(httpClient),
		jwt.WithIssuerAndKeySet(jwt.Issuer(cfg.Issuer), keyStore, string(InternalSigningAlgorithm)),
	}

	for _, issuer := range cfg.SubjectTokenIssuers.Issuers() {
		opts = append(opts, jwt.WithIssuer(issuer))
	}

	tokenExchangeVerifier, err := jwt.NewTokenVerifier(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating token exchange verifier: %w", err)
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
	SubjectTokenClaims *jwt.AccessTokenClaims
	Client             *Client
	Roles              Roles
}

func (a *AuthorizationServer) AuthorizeRequest(ctx context.Context, request TokenRequest) (*AuthorizationResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "verify_client_assertion")
	clientAuthClaims, err := a.ClientAuthVerifier.Verify(ctx, request.GetClientAuthCredentials().ClientAssertion)
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

	var claims *jwt.AccessTokenClaims
	// TODO: move verify subject token to a func on request, by passing in verifier? noop on client credentials, verify on token exchange
	if request.GrantType() == oidc.GrantTypeTokenExchange {
		te, ok := request.(*TokenExchangeRequest)
		if !ok {
			return nil, fmt.Errorf("request is %T, want *TokenExchangeRequest", request)
		}
		finishStep = a.Metrics.StartTokenStep(ctx, "verify_subject_token")
		claims, err = a.TokenExchangeVerifier.Verify(ctx, te.SubjectToken, func(claims *jwt.AccessTokenClaims) error {
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

	slog.LogAttrs(ctx, slog.LevelInfo, "token issued", a.logAttrs(result)...)
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

func (a *AuthorizationServer) verifySTSIssuedSubjectTokenClaims(claims *jwt.AccessTokenClaims, clientID string) error {
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

func (a *AuthorizationServer) logAttrs(result *AuthorizationResult) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("grant_type", string(result.GrantType)),
		slog.String("client_id", result.Client.ID),
		slog.String("target_type", result.Target.GetType()),
		slog.String("target", result.Target.GetValue()),
		slog.Int("role_count", len(result.Roles)),
	}

	if result.SubjectTokenClaims != nil {
		subjectIssuer := result.SubjectTokenClaims.Issuer
		attrs = append(attrs, slog.String("subject_token_issuer", subjectIssuer))

		if idpName, ok := a.SubjectTokenIssuers[jwt.Issuer(subjectIssuer)]; ok {
			attrs = append(attrs, slog.String("idp_name", idpName))
		}
	}

	return attrs
}
