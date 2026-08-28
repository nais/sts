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
	ClientAuthVerifiers    []TokenVerifier
	ClientStore            ClientStore
	Issuer                 string
	KeyStore               KeyStore
	TokenExchangeVerifiers []TokenVerifier
	Signer                 jose.Signer
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
	clientAuthVerifier1, err := NewTokenVerifier(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}
	clientAuthVerifiers := []TokenVerifier{*clientAuthVerifier1}
	tokenExchangeVerifiers := []TokenVerifier{*clientAuthVerifier1}

	alg := jose.RS256 // TODO: consider stronger algorithm
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	return &AuthorizationServer{
		ClientAuthVerifiers: clientAuthVerifiers,
		ClientStore: ClientStore{
			Clients: clients,
		},
		Issuer: cfg.Issuer,
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
		TokenExchangeVerifiers: tokenExchangeVerifiers,
		Signer:                 signer,
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
	// TODO: select correct issuer for verification
	// TODO: audience should be configurable
	authClaims, err := a.ClientAuthVerifiers[0].Verify(ctx, request.GetClientAuthCredentials().ClientAssertion)
	if err != nil || authClaims.Subject != client.WorkloadSubject || len(authClaims.Audience) != 1 || authClaims.Audience[0] != a.Issuer {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid")
	}

	target, err := request.Target()
	if err != nil {
		return nil, err
	}

	var claims *AccessTokenClaims
	if te, ok := request.(*TokenExchangeRequest); ok {
		// TODO: choose correct issuer for validation
		claims, err = a.TokenExchangeVerifiers[0].Verify(ctx, te.SubjectToken)
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
