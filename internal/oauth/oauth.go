package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/config"
	rp "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type OAuthClient struct {
	WorkloadIssuer    string   `yaml:"workloadIssuer"`
	WorkloadSubject   string   `yaml:"workloadSubject"`
	AllowedAudiences  []string `yaml:"allowedAudiences"`
	AccessControlList AccessControlList

	// TODO: temporary
	Client
}

type TrustedIssuer struct {
	Issuer   string
	JwksURI  string
	verifier *TokenVerifier
}

func (t *TrustedIssuer) Verify(ctx context.Context, token string) (*AccessTokenClaims, error) {
	return t.verifier.Verify(ctx, token, t.Issuer)
}

type KeyStore struct {
	jose.JSONWebKeySet
}

type KeyID string

type AccessControlList struct {
	Allowed []AccessControlListEntry
}

type AccessControlListEntry struct {
	OAuthClient
	Roles []string
}

type ClientStore struct {
	Clients map[ClientID]OAuthClient
}

type ClientID string

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

	clients := map[ClientID]OAuthClient{
		"tenant:cluster:namespace:workload": {
			WorkloadIssuer:    issuer,
			WorkloadSubject:   subject,
			AllowedAudiences:  []string{"http://some-api.nais.example"},
			AccessControlList: AccessControlList{},
			Client: Client{
				id:               "tenant:cluster:namespace:workload",
				WorkloadIssuer:   issuer,
				WorkloadSubject:  subject,
				AllowedAudiences: []string{"http://some-api.nais.example"},
			},
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

type TokenExchangeRequest struct {
	oidc.TokenExchangeRequest
}

func (t *TokenExchangeRequest) GrantType() oidc.GrantType {
	return t.GrantType()
}

type ClientCredentialsRequest struct {
	oidc.ClientCredentialsRequest
}

func (t *ClientCredentialsRequest) GrantType() oidc.GrantType {
	return t.GrantType()
}

func (a *AuthorizationServer) AuthorizeClient(_ context.Context, request oidc.TokenRequest, client OAuthClient) error {
	switch r := request.(type) {
	case *ClientCredentialsRequest:
		if !slices.Contains(client.AllowedAudiences, r.Scope[0]) {
			return oidc.ErrInvalidTarget().WithDescription("requested scope is not allowed for this client")
		}
	case *TokenExchangeRequest:
		if !slices.Contains(client.AllowedAudiences, r.Audience[0]) {
			return oidc.ErrInvalidTarget().WithDescription("requested audience is not allowed for this client")
		}
	default:
		return oidc.ErrInvalidRequest().WithDescription("unsupported grant type")
	}
	return nil
}

func (a *AuthorizationServer) VerifyClient(ctx context.Context, request *op.Request[op.ClientCredentials]) (op.Client, error) {
	credentials := request.Data
	if credentials.ClientID == "" || credentials.ClientAssertion == "" ||
		credentials.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion || credentials.ClientSecret != "" {
		return nil, oidc.ErrInvalidClient().WithDescription("workload identity client assertion required")
	}
	client, ok := a.ClientStore.Clients[ClientID(credentials.ClientID)]
	if !ok {
		return nil, oidc.ErrInvalidClient()
	}
	// TODO: select correct issuer for verification
	// TODO: audience should be configurable
	claims, err := a.ClientAuthIssuers[0].Verify(ctx, credentials.ClientAssertion)
	if err != nil || claims.Subject != client.WorkloadSubject || len(claims.Audience) != 1 || claims.Audience[0] != a.Issuer {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid")
	}
	return &client, nil
}

func (a *AuthorizationServer) ClientCredentialsExchange(ctx context.Context, request *op.ClientRequest[oidc.ClientCredentialsRequest]) (*op.Response, error) {
	client, ok := request.Client.(*OAuthClient)
	if !ok || len(request.Data.Scope) != 1 || !client.allowsAudience(request.Data.Scope[0]) {
		return nil, oidc.ErrInvalidTarget().WithDescription("requested scope is not allowed for this client")
	}
	accessToken, err := CreateClientCredentialsAccessToken(
		a.Issuer,
		client.GetID(),
		oidc.Audience(request.Data.Scope),
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

func (a *AuthorizationServer) TokenExchange(ctx context.Context, request *op.ClientRequest[oidc.TokenExchangeRequest]) (*op.Response, error) {
	if request.Data.ActorToken != "" || request.Data.ActorTokenType != "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("actor_token is not supported")
	}
	if request.Data.SubjectToken == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token missing")
	}
	if request.Data.SubjectTokenType == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type missing")
	}
	if !request.Data.SubjectTokenType.IsSupported() {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type is not supported")
	}
	if request.Data.RequestedTokenType != oidc.AccessTokenType {
		return nil, oidc.ErrInvalidRequest().WithDescription("only access tokens can be requested")
	}
	if len(request.Data.Audience) != 1 {
		return nil, oidc.ErrInvalidTarget().WithDescription("requested audience is not allowed for this client")
	}

	// TODO: replace with verifier to Verify subject token, create JwtTokenRequest and call CreateAccessToken to create the new access token
	// remember to check acl aswell
	client, ok := request.Client.(*OAuthClient)
	if !ok || len(request.Data.Audience) != 1 || !client.allowsAudience(request.Data.Audience[0]) {
		return nil, oidc.ErrInvalidTarget().WithDescription("requested audience is not allowed for this client")
	}

	// TODO: choose correct issuer for validation
	subjectTokenClaims, err := a.TokenExchangeIssuers[0].Verify(ctx, request.Data.SubjectToken)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("subject token is invalid")
	}

	accessToken, err := CreateTokenExchangeAccessToken(
		a.Issuer,
		subjectTokenClaims.Subject,
		client.GetID(),
		request.Data.Audience,
		nil,
		1*time.Hour,
		subjectTokenClaims.Claims,
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
