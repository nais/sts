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
	verifier      *tokenVerifier
}

func NewAuthServer(issuer string, endpoints *op.Endpoints, registrations *RegistrationStore) (op.Server, error) {
	verifier := newTokenVerifier()
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
	audience := request.Form["audience"]
	client, ok := request.Client.(*Client)
	if !ok || len(audience) != 1 || !client.allowsAudience(audience[0]) {
		return nil, oidc.ErrInvalidTarget()
	}
	tokenRequest := &oidc.JWTTokenRequest{
		Subject:  client.GetID(),
		Audience: audience,
		Scopes:   request.Data.Scope,
	}
	response, err := op.CreateClientCredentialsTokenResponse(ctx, tokenRequest, s.legacy.Provider(), client)
	if err != nil {
		return nil, err
	}
	return op.NewResponse(response), nil
}

func (s *server) Keys(ctx context.Context, request *op.Request[struct{}]) (*op.Response, error) {
	return s.legacy.Keys(ctx, request)
}

func (s *server) TokenExchange(ctx context.Context, request *op.ClientRequest[oidc.TokenExchangeRequest]) (*op.Response, error) {
	if request.Data.ActorToken != "" || request.Data.ActorTokenType != "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("actor_token is not supported")
	}
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
	claims, err := s.verifier.verify(ctx, credentials.ClientAssertion, client.WorkloadIssuer)
	if err != nil || claims.Subject != client.WorkloadSubject || len(claims.Audience) != 1 || claims.Audience[0] != s.issuer {
		return nil, oidc.ErrInvalidClient().WithDescription("client assertion is invalid")
	}
	return client, nil
}
