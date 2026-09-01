package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/nais/sts/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const developmentWorkloadIssuer = "https://container.googleapis.com/v1/projects/nais-dev-cdea/locations/europe-north1/clusters/nais-dev"

type AuthorizationServer struct {
	ClientAuthVerifier    *TokenVerifier
	ClientStore           ClientStore
	ExpectedAudience      string
	Issuer                string
	KeyStore              KeyStore
	TokenExchangeVerifier *TokenVerifier
}

func NewAuthorizationServer(ctx context.Context, cfg config.Config, clientStore ClientStore, keyStore KeyStore) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewTokenVerifier(ctx, developmentWorkloadIssuer)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}
	tokenExchangeVerifier, err := NewTokenVerifier(ctx, developmentWorkloadIssuer)
	if err != nil {
		return nil, fmt.Errorf("creating token exchange verifier: %w", err)
	}

	return &AuthorizationServer{
		ClientAuthVerifier:    clientAuthVerifier,
		ClientStore:           clientStore,
		ExpectedAudience:      cfg.ExpectedAudience,
		Issuer:                cfg.Issuer,
		KeyStore:              keyStore,
		TokenExchangeVerifier: tokenExchangeVerifier,
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
