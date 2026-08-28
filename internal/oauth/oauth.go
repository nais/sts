package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/config"
	rp "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type TrustedIssuer struct {
	Issuer   string
	JwksURI  string
	verifier *TokenVerifier
}

func (t *TrustedIssuer) Verify(ctx context.Context, token string) (*AccessTokenClaims, error) {
	return t.verifier.Verify(ctx, token, t.Issuer)
}

type AuthorizationServer struct {
	ClientAuthIssuers    []TrustedIssuer
	ClientStore          ClientStore
	Issuer               string
	KeyStore             KeyStore
	TokenExchangeIssuers []TrustedIssuer
	Signer               jose.Signer
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

	metadata, err := rp.Discover(ctx, issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("discover metadata from issuer %q: %w", issuer, err)
	}

	clients := map[ClientID]*OAuthClient{
		"tenant:cluster:namespace:workload": {
			ID:                "tenant:cluster:namespace:workload",
			WorkloadIssuer:    issuer,
			WorkloadSubject:   subject,
			AllowedAudiences:  []string{"http://some-api.nais.example"},
			AccessControlList: AccessControlList{},
		},
	}

	clientAuthIssuers := []TrustedIssuer{
		{
			Issuer:   issuer,
			JwksURI:  metadata.JwksURI,
			verifier: NewTokenVerifier(),
		},
	}

	tokenExchangeIssuers := []TrustedIssuer{
		{
			Issuer:   issuer,
			JwksURI:  metadata.JwksURI,
			verifier: NewTokenVerifier(),
		},
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
		ClientAuthIssuers: clientAuthIssuers,
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
		TokenExchangeIssuers: tokenExchangeIssuers,
		Signer:               signer,
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
	authClaims, err := a.ClientAuthIssuers[0].Verify(ctx, request.GetClientAuthCredentials().ClientAssertion)
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
		claims, err = a.TokenExchangeIssuers[0].Verify(ctx, te.SubjectToken)
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

func (a *AuthorizationServer) ClientCredentialsExchange(ctx context.Context, request *ClientCredentialsRequest) (*op.Response, error) {
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

	return op.NewResponse(&oidc.AccessTokenResponse{
		AccessToken: signed,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(accessToken.ExpiresIn().Seconds()),
	}), nil
}

func (a *AuthorizationServer) TokenExchange(ctx context.Context, request *TokenExchangeRequest) (*op.Response, error) {
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

	return op.NewResponse(&oidc.TokenExchangeResponse{
		AccessToken:     signed,
		IssuedTokenType: oidc.AccessTokenType,
		TokenType:       oidc.BearerToken,
		ExpiresIn:       uint64(accessToken.ExpiresIn().Seconds()),
	}), nil

}

func (a *AuthorizationServer) Keys(ctx context.Context) (*op.Response, error) {
	keys := a.KeyStore.Keys
	publicKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		publicKeys[i] = key.Public()
	}
	return op.NewResponse(&jose.JSONWebKeySet{Keys: publicKeys}), nil
}
