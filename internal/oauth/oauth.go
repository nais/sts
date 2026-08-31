package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthorizationServer struct {
	ClientAuthVerifier    *TokenVerifier
	ClientStore           ClientStore
	ExpectedAudience      string
	Issuer                string
	KeyStore              KeyStore
	TokenExchangeVerifier *TokenVerifier
	Signer                jose.Signer
}

func NewAuthorizationServer(ctx context.Context, cfg config.Config) (*AuthorizationServer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	const (
		issuer  = "https://container.googleapis.com/v1/projects/nais-dev-cdea/locations/europe-north1/clusters/nais-dev"
		subject = "system:serviceaccount:trong:debug"
	)

	clients := map[ClientID]*OAuthClient{
		"tenant:cluster:namespace:workload": {
			ID:                "tenant:cluster:namespace:workload",
			WorkloadIssuer:    issuer,
			WorkloadSubject:   subject,
			AllowedAudiences:  []string{"http://some-api.nais.example"},
			AccessControlList: AccessControlList{},
		},
	}
	clientAuthVerifier, err := NewTokenVerifier(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}
	tokenExchangeVerifier, err := NewTokenVerifier(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating token exchange verifier: %w", err)
	}

	alg := jose.RS256 // TODO: consider stronger algorithm
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	return &AuthorizationServer{
		ClientAuthVerifier: clientAuthVerifier,
		ClientStore: ClientStore{
			Clients: clients,
		},
		ExpectedAudience: cfg.ExpectedAudience,
		Issuer:           cfg.Issuer,
		KeyStore: KeyStore{
			JSONWebKeySet: jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       key,
						KeyID:     "key1",
						Algorithm: string(alg),
						Use:       "sig",
					},
				},
			},
		},
		TokenExchangeVerifier: tokenExchangeVerifier,
		Signer:                signer,
	}, nil
}

type AuthorizationResult struct {
	Target             Target
	SubjectTokenClaims *AccessTokenClaims
	Client             *OAuthClient
}

func (a *AuthorizationServer) AuthorizeRequest(ctx context.Context, request TokenRequest) (*AuthorizationResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	client, ok := a.ClientStore.Clients[ClientID(request.GetClientAuthCredentials().ClientID)]
	if !ok {
		return nil, oidc.ErrInvalidClient()
	}

	_, err := a.ClientAuthVerifier.Verify(ctx, request.GetClientAuthCredentials().ClientAssertion, func(claims *AccessTokenClaims) error {
		if claims.Subject != client.WorkloadSubject {
			return oidc.ErrInvalidClient().WithDescription("subject is invalid: got %q, want %q", claims.Subject, client.WorkloadSubject)
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

	if err = a.ClientStore.AuthorizeTarget(client, target); err != nil {
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
	signed, err := accessToken.Sign(a.Signer)
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

	signed, err := accessToken.Sign(a.Signer)
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
	keys := a.KeyStore.Keys
	publicKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		publicKeys[i] = key.Public()
	}
	return &Response{
		Data: &jose.JSONWebKeySet{Keys: publicKeys},
	}, nil
}
