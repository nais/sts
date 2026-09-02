package oauth

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthorizationServer struct {
	ClientAuthVerifier    *TokenVerifier
	ClientStore           ClientStore
	KeyStore              KeyStore
	TokenExchangeVerifier *TokenVerifier
	AuthorizationServerConfig
}

type AuthorizationServerConfig struct {
	Issuer              string   `env:"ISSUER, default=http://localhost:8080"`
	ExpectedAudience    string   `env:"EXPECTED_AUDIENCE, default=nais"`
	ClientAuthIssuers   []Issuer `env:"CLIENT_AUTH_ISSUERS, required"`
	SubjectTokenIssuers []Issuer `env:"SUBJECT_TOKEN_ISSUERS, required"`
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

func NewAuthorizationServer(ctx context.Context, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore) (*AuthorizationServer, error) {
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
		AuthorizationServerConfig: cfg,
	}, nil
}

type AuthorizationResult struct {
	Target             Target
	SubjectTokenClaims *AccessTokenClaims
	Client             *Client
}

func (a *AuthorizationServer) AuthorizeRequest(ctx context.Context, request TokenRequest) (*AuthorizationResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	client, err := a.ClientStore.Get(ctx, ClientID(request.GetClientAuthCredentials().ClientID))
	if err != nil {
		return nil, err
	}

	_, err = a.ClientAuthVerifier.Verify(ctx, request.GetClientAuthCredentials().ClientAssertion, func(claims *AccessTokenClaims) error {
		if claims.Subject != client.ID {
			// TODO: correct this check
			return oidc.ErrInvalidClient().WithDescription("subject is invalid: got %q, want %q", claims.Subject, client.ID)
		}
		if len(claims.Audience) != 1 {
			return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %d audiences, want 1", len(claims.Audience))
		}
		if claims.Audience[0] != a.ExpectedAudience {
			return oidc.ErrInvalidClient().WithDescription("audience is invalid: got %q, want %q", claims.Audience[0], a.ExpectedAudience)
		}
		return nil
	})
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid: %+v", err)
	}

	target, err := request.Target()
	if err != nil {
		return nil, err
	}

	var claims *AccessTokenClaims
	if te, ok := request.(*TokenExchangeRequest); ok {
		claims, err = a.TokenExchangeVerifier.Verify(ctx, te.SubjectToken)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("subject token is invalid")
		}
	}

	if err = a.ClientStore.AuthorizeTarget(ctx, ClientID(client.ID), target); err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		Target:             target,
		SubjectTokenClaims: claims,
		Client:             client,
	}, nil
}

func (a *AuthorizationServer) ClientCredentialsExchange(ctx context.Context, request *ClientCredentialsRequest) (*Response, error) {
	result, err := a.AuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	accessToken, err := CreateClientCredentialsAccessToken(
		a.Issuer,
		result.Client.ID,
		result.Target.AsAudience(),
		nil,
		1*time.Hour,
	)
	if err != nil {
		return nil, err
	}
	signer, err := a.KeyStore.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}
	signed, err := accessToken.Sign(signer)
	if err != nil {
		return nil, err
	}

	return &Response{
		Data: &oidc.AccessTokenResponse{
			AccessToken: signed,
			TokenType:   oidc.BearerToken,
			ExpiresIn:   uint64(accessToken.ExpiresIn().Seconds()),
		},
	}, nil
}

func (a *AuthorizationServer) TokenExchange(ctx context.Context, request *TokenExchangeRequest) (*Response, error) {
	result, err := a.AuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	accessToken, err := CreateTokenExchangeAccessToken(
		a.Issuer,
		result.SubjectTokenClaims.Subject,
		result.Client.ID,
		request.Audience,
		nil,
		1*time.Hour,
		result.SubjectTokenClaims.Claims,
	)
	if err != nil {
		return nil, err
	}

	signer, err := a.KeyStore.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}
	signed, err := accessToken.Sign(signer)
	if err != nil {
		return nil, err
	}

	return &Response{
		Data: &oidc.TokenExchangeResponse{
			AccessToken:     signed,
			IssuedTokenType: oidc.AccessTokenType,
			TokenType:       oidc.BearerToken,
			ExpiresIn:       uint64(accessToken.ExpiresIn().Seconds()),
		},
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
