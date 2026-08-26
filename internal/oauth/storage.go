package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var (
	errNotSupported = errors.New("not supported")

	_ op.Storage                            = &Storage{}
	_ op.TokenExchangeStorage               = &Storage{}
	_ op.TokenExchangeTokensVerifierStorage = &Storage{}
)

type Storage struct {
	unsupportedStorage
	registrations *RegistrationStore
	verifier      *TokenVerifier
	signingKey    signingKey
}

type signingKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

type publicKey struct{ signingKey }

// unsupportedStorage satisfies the broad legacy op.Storage interface.
// The whitelist server never calls these methods.
type unsupportedStorage struct{}

func newStorage(registrations *RegistrationStore, verifier *TokenVerifier) *Storage {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Storage{
		registrations: registrations,
		verifier:      verifier,
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       key,
		},
	}
}

func (k *signingKey) ID() string                                  { return k.id }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.algorithm }

func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *publicKey) ID() string                         { return k.id }
func (k *publicKey) Key() any                           { return &k.key.PublicKey }
func (k *publicKey) Use() string                        { return "sig" }

func (*Storage) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return uuid.NewString(), time.Now().Add(5 * time.Minute), nil
}

// TODO: Persist token exchange requests for audit logging.
func (*Storage) CreateTokenExchangeRequest(context.Context, op.TokenExchangeRequest) error {
	return nil
}

func (s *Storage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	client, ok := s.registrations.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return client, nil
}

func (*Storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	// TODO: Add the approved Nais claims for issued tokens.
	return nil, nil
}

func (*Storage) GetPrivateClaimsFromTokenExchangeRequest(context.Context, op.TokenExchangeRequest) (map[string]any, error) {
	// TODO: Add the approved subject-token claims for exchanged tokens.
	return nil, nil
}

func (*Storage) Health(context.Context) error { return nil }

func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signingKey}}, nil
}

func (*Storage) SetUserinfoFromTokenExchangeRequest(context.Context, *oidc.UserInfo, op.TokenExchangeRequest) error {
	return errNotSupported
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

func (s *Storage) ValidateTokenExchangeRequest(_ context.Context, request op.TokenExchangeRequest) error {
	if request.GetExchangeActorTokenIDOrToken() != "" {
		return oidc.ErrInvalidRequest().WithDescription("actor_token is not supported")
	}
	if request.GetRequestedTokenType() == "" {
		request.SetRequestedTokenType(oidc.AccessTokenType)
	}
	if request.GetRequestedTokenType() != oidc.AccessTokenType {
		return oidc.ErrInvalidRequest().WithDescription("only access tokens can be requested")
	}
	if len(request.GetAudience()) != 1 {
		return oidc.ErrInvalidTarget()
	}
	client, ok := s.registrations.clients[request.GetClientID()]
	if !ok || !client.allowsAudience(request.GetAudience()[0]) {
		return oidc.ErrInvalidTarget()
	}
	return nil
}

func (*Storage) VerifyExchangeActorToken(context.Context, string, oidc.TokenType) (string, string, map[string]any, error) {
	return "", "", nil, fmt.Errorf("actor_token is not supported")
}

func (s *Storage) VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType oidc.TokenType) (string, string, map[string]any, error) {
	if tokenType != oidc.AccessTokenType {
		return "", "", nil, fmt.Errorf("only access token subject tokens are supported")
	}
	unverified := new(oidc.TokenClaims)
	if _, err := oidc.ParseToken(token, unverified); err != nil {
		return "", "", nil, err
	}
	_, ok := s.registrations.subjectTokenIssuers[unverified.Issuer]
	if !ok {
		return "", "", nil, fmt.Errorf("subject token issuer is not registered")
	}
	claims, err := s.verifier.Verify(ctx, token, unverified.Issuer)
	if err != nil {
		return "", "", nil, err
	}
	return token, claims.Subject, claimsMap(claims), nil
}

func (unsupportedStorage) AuthorizeClientIDSecret(context.Context, string, string) error {
	return fmt.Errorf("client secrets are not supported")
}

func (unsupportedStorage) AuthRequestByCode(context.Context, string) (op.AuthRequest, error) {
	return nil, errNotSupported
}

func (unsupportedStorage) AuthRequestByID(context.Context, string) (op.AuthRequest, error) {
	return nil, errNotSupported
}

func (unsupportedStorage) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, errNotSupported
}

func (unsupportedStorage) CreateAuthRequest(context.Context, *oidc.AuthRequest, string) (op.AuthRequest, error) {
	return nil, errNotSupported
}

func (unsupportedStorage) DeleteAuthRequest(context.Context, string) error {
	return errNotSupported
}

func (unsupportedStorage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errNotSupported
}

func (unsupportedStorage) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", errNotSupported
}

func (unsupportedStorage) RevokeToken(context.Context, string, string, string) *oidc.Error {
	return oidc.ErrUnsupportedGrantType()
}

func (unsupportedStorage) SaveAuthCode(context.Context, string, string) error {
	return errNotSupported
}

func (unsupportedStorage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errNotSupported
}

func (unsupportedStorage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

func (unsupportedStorage) SetUserinfoFromToken(context.Context, *oidc.UserInfo, string, string, string) error {
	return errNotSupported
}

func (unsupportedStorage) TerminateSession(context.Context, string, string) error {
	return errNotSupported
}

func (unsupportedStorage) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, errNotSupported
}

func (unsupportedStorage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errNotSupported
}
