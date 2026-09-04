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
	ClientAuthVerifier    *TokenVerifier
	ClientStore           ClientStore
	KeyStore              KeyStore
	TokenExchangeVerifier *TokenVerifier
	Metrics               *stsmetrics.Metrics
	AuthorizationServerConfig
}

type AuthorizationServerConfig struct {
	Issuer              string        `env:"ISSUER, default=http://localhost:8080"`
	ExpectedAudience    string        `env:"EXPECTED_AUDIENCE, default=nais"`
	ClientAuthIssuers   []Issuer      `env:"CLIENT_AUTH_ISSUERS, required"`
	SubjectTokenIssuers []Issuer      `env:"SUBJECT_TOKEN_ISSUERS, required"`
	TokenExpiry         time.Duration `env:"TOKEN_EXPIRY, default=1h"`
}

func (c AuthorizationServerConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer must not be empty")
	}
	issuer, err := url.Parse(c.Issuer)
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
	return nil
}

func NewAuthorizationServer(ctx context.Context, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore, metrics *stsmetrics.Metrics) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewTokenVerifier(ctx, cfg.ClientAuthIssuers...)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}
	tokenExchangeVerifier, err := NewTokenVerifier(ctx, cfg.SubjectTokenIssuers...)
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

	start := time.Now()
	clientAuthClaims, err := a.ClientAuthVerifier.Verify(ctx, request.GetClientAuthCredentials().ClientAssertion, func(claims *AccessTokenClaims) error {
		if len(claims.Audience) != 1 {
			return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %d audiences, want 1", len(claims.Audience))
		}
		if claims.Audience[0] != a.ExpectedAudience {
			return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %q, want %q", claims.Audience[0], a.ExpectedAudience)
		}
		return nil
	})
	a.Metrics.ObserveTokenStep(ctx, "verify_client_assertion", start, err)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid: %+v", err)
	}

	target, err := request.Target()
	if err != nil {
		return nil, err
	}

	start = time.Now()
	client, err := a.ClientStore.Get(ctx, clientAuthClaims)
	a.Metrics.ObserveTokenStep(ctx, "get_client", start, err)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("client not found: %+v", err)
	}

	var claims *AccessTokenClaims
	if request.GrantType() == oidc.GrantTypeTokenExchange {
		te, ok := request.(*TokenExchangeRequest)
		if !ok {
			return nil, oidc.ErrInvalidRequest().WithDescription("could not parse request as TokenExchangeRequest")
		}
		start = time.Now()
		claims, err = a.TokenExchangeVerifier.Verify(ctx, te.SubjectToken)
		a.Metrics.ObserveTokenStep(ctx, "verify_subject_token", start, err)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("subject token is invalid")
		}
	}

	start = time.Now()
	roles, err := a.ClientStore.AuthorizeTarget(ctx, ClientID(client.ID), target)
	a.Metrics.ObserveTokenStep(ctx, "authorize_target", start, err)
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
	// TODO: figure out what to set in actor
	subject := result.Client.ID
	var claims map[string]json.RawMessage

	if result.SubjectTokenClaims != nil {
		subject = result.SubjectTokenClaims.Subject
		claims = result.SubjectTokenClaims.Claims
	}
	accessToken, err := CreateAccessToken(
		a.Issuer,
		subject,
		result.Client.ID,
		result.Target.AsAudience(),
		nil,
		a.TokenExpiry,
		result.Roles,
		claims,
	)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	signer, err := a.KeyStore.Signer(ctx)
	a.Metrics.ObserveTokenStep(ctx, "get_signer", start, err)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}
	start = time.Now()
	signed, err := accessToken.Sign(signer)
	a.Metrics.ObserveTokenStep(ctx, "sign_token", start, err)
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
