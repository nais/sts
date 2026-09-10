package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

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

type AuthorizationServerConfig struct {
	Issuer              Issuer        `yaml:"issuer"`
	ExpectedAudience    string        `yaml:"expectedAudience"`
	ClientAuthIssuers   []Issuer      `yaml:"clientAuthIssuers"`
	SubjectTokenIssuers []Issuer      `yaml:"subjectTokenIssuers"`
	TokenExpiry         time.Duration `yaml:"tokenExpiry"`
}

func (c AuthorizationServerConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer must not be empty")
	}
	issuer, err := url.Parse(string(c.Issuer))
	if err != nil || !issuer.IsAbs() || issuer.Host == "" {
		return fmt.Errorf("issuer must be an absolute URL")
	}
	isLoopback := func(host string) bool {
		return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
	}
	if issuer.Scheme != "https" && (issuer.Scheme != "http" || !isLoopback(issuer.Hostname())) {
		return fmt.Errorf("issuer must use https, except for localhost or loopback http URLs")
	}
	if len(c.ClientAuthIssuers) == 0 {
		return fmt.Errorf("client auth issuers must not be empty")
	}
	if len(c.SubjectTokenIssuers) == 0 {
		return fmt.Errorf("subject token issuers must not be empty")
	}
	if c.ExpectedAudience == "" {
		return fmt.Errorf("expected audience must not be empty")
	}
	if c.TokenExpiry <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}
	return nil
}

func NewAuthorizationServer(ctx context.Context, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore, metrics *stsmetrics.Metrics) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewClientAuthTokenVerifier(ctx, cfg.ClientAuthIssuers)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}

	tokenExchangeVerifier, err := NewTokenExchangeTokenVerifier(ctx, cfg, keyStore)
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
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid: %+v", err)
	}

	target, err := request.Target()
	if err != nil {
		return nil, err
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "get_client")
	client, err := a.ClientStore.Get(ctx, clientAuthClaims)
	finishStep(err)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("client not found: %+v", err)
	}

	var claims *AccessTokenClaims
	if request.GrantType() == oidc.GrantTypeTokenExchange {
		te, ok := request.(*TokenExchangeRequest)
		if !ok {
			return nil, oidc.ErrInvalidRequest().WithDescription("could not parse request as TokenExchangeRequest")
		}
		finishStep = a.Metrics.StartTokenStep(ctx, "verify_subject_token")
		claims, err = a.TokenExchangeVerifier.Verify(ctx, te.SubjectToken, a.verifyTokenExchangeClaims)
		finishStep(err)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("subject token is invalid: %s", err)
		}
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "authorize_target")
	roles, err := a.ClientStore.AuthorizeTarget(ctx, ClientID(client.ID), target)
	finishStep(err)
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

func (a *AuthorizationServer) GrantHandler(ctx context.Context, request TokenRequest) (*Response, error) {
	finishGrant := a.Metrics.StartTokenGrant(ctx, request.GrantType())
	var err error
	defer func() { finishGrant(err) }()

	result, err := a.AuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	data, err := a.CreateTokenResponse(ctx, result)
	if err != nil {
		return nil, err
	}
	return &Response{
		Data: data,
	}, nil
}

func (a *AuthorizationServer) Keys(ctx context.Context) (*Response, error) {
	keys, err := a.KeyStore.PublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get public keys: %w", err)
	}
	return &Response{
		Data: keys,
	}, nil
}

func (a *AuthorizationServer) CreateTokenResponse(ctx context.Context, result *AuthorizationResult) (*AccessTokenResponse, error) {
	accessToken, err := CreateAccessToken(a.Issuer, a.TokenExpiry, result)
	if err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "get_signer")
	signer, err := a.KeyStore.Signer(ctx)
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
	if len(claims.Audience) != 1 {
		return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %d audiences, want 1", len(claims.Audience))
	}
	if claims.Audience[0] != a.ExpectedAudience {
		return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %q, want %q", claims.Audience[0], a.ExpectedAudience)
	}
	return nil
}

func (a *AuthorizationServer) verifyTokenExchangeClaims(claims *AccessTokenClaims) error {
	if claims.Issuer != string(a.Issuer) {
		return nil
	}

	var grantType oidc.GrantType
	rawGrantType, ok := claims.Claims["urn:nais:grant_type"]
	if !ok {
		return oidc.ErrInvalidRequest().WithDescription("grant_type claim is missing")
	}
	if err := json.Unmarshal(rawGrantType, &grantType); err != nil {
		return oidc.ErrInvalidRequest().WithDescription("grant_type claim must be a string")
	}
	if grantType != oidc.GrantTypeTokenExchange {
		return oidc.ErrInvalidRequest().WithDescription("grant_type claim is invalid: got %q, want %q", grantType, oidc.GrantTypeTokenExchange)
	}
	return nil
}
