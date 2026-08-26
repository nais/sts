package oauth

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type server struct {
	op.UnimplementedServer
	legacy        *op.LegacyServer
	issuer        string
	registrations *RegistrationStore
	verifier      *TokenVerifier
}

func NewAuthServer(issuer string, endpoints *op.Endpoints, registrations *RegistrationStore) (op.Server, error) {
	verifier := NewTokenVerifier()
	provider, err := op.NewProvider(
		&op.Config{AuthMethodPrivateKeyJWT: true},
		newStorage(registrations, verifier),
		op.StaticIssuer(issuer),
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, err
	}

	s := &server{
		legacy:        op.NewLegacyServer(provider, *endpoints),
		issuer:        issuer,
		registrations: registrations,
		verifier:      verifier,
	}
	return s, nil
}

func (s *server) ClientCredentialsExchange(ctx context.Context, request *op.ClientRequest[oidc.ClientCredentialsRequest]) (*op.Response, error) {
	client, ok := request.Client.(*Client)
	if !ok || len(request.Data.Scope) != 1 || !client.allowsAudience(request.Data.Scope[0]) {
		return nil, oidc.ErrInvalidTarget()
	}
	tokenRequest := &oidc.JWTTokenRequest{
		Subject: client.GetID(),
		Scopes:  request.Data.Scope,
	}
	accessToken, _, validity, err := op.CreateAccessToken(ctx, tokenRequest, client.AccessTokenType(), s.legacy.Provider(), client, "")
	if err != nil {
		return nil, err
	}

	return op.NewResponse(&oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       tokenRequest.GetScopes(),
	}), nil
}

func (s *server) Keys(ctx context.Context, request *op.Request[struct{}]) (*op.Response, error) {
	return s.legacy.Keys(ctx, request)
}

func (s *server) TokenExchange(ctx context.Context, request *op.ClientRequest[oidc.TokenExchangeRequest]) (*op.Response, error) {
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
	if request.Data.RequestedTokenType != "" && !request.Data.RequestedTokenType.IsSupported() {
		return nil, oidc.ErrInvalidRequest().WithDescription("requested_token_type is not supported")
	}
	// TODO: replace with verifier to Verify subject token, create JwtTokenRequest and call CreateAccessToken to create the new access token
	// remember to check acl aswell
	return s.legacy.TokenExchange(ctx, request)
}

func (s *server) VerifyClient(ctx context.Context, request *op.Request[op.ClientCredentials]) (op.Client, error) {
	credentials := request.Data
	if credentials.ClientID == "" || credentials.ClientAssertion == "" ||
		credentials.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion || credentials.ClientSecret != "" {
		return nil, oidc.ErrInvalidClient().WithDescription("workload identity client assertion required")
	}
	client, ok := s.registrations.clients[credentials.ClientID]
	if !ok {
		return nil, oidc.ErrInvalidClient()
	}
	claims, err := s.verifier.Verify(ctx, credentials.ClientAssertion, client.WorkloadIssuer)
	if err != nil || claims.Subject != client.WorkloadSubject || len(claims.Audience) != 1 || claims.Audience[0] != s.issuer {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid")
	}
	return client, nil
}
