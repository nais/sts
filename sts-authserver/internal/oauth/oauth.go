package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/jwt"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthorizationServer struct {
	ClientAuthVerifier    *jwt.TokenVerifier
	ClientStore           ClientStore
	KeyStore              KeyStore
	TokenExchangeVerifier *jwt.TokenVerifier
	Metrics               *stsmetrics.Metrics
	AuthorizationServerConfig
}

func NewAuthorizationServer(ctx context.Context, httpClient *http.Client, cfg AuthorizationServerConfig, clientStore ClientStore, keyStore KeyStore, metrics *stsmetrics.Metrics) (*AuthorizationServer, error) {
	clientAuthVerifier, err := NewClientAuthTokenVerifier(ctx,
		httpClient,
		cfg.ClientAuthIssuerURLs(),
		cfg.ExpectedAudience,
		cfg.MaxClientAuthTokenLifetime,
	)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}

	opts := []jwt.TokenVerifierOption{
		jwt.WithHttpClient(httpClient),
		jwt.WithIssuerAndKeySet(jwt.Issuer(cfg.Issuer), keyStore, string(InternalSigningAlgorithm)),
		jwt.WithIssuersFrom(clientAuthVerifier),
	}

	for _, issuer := range cfg.ExternalIssuers.Issuers() {
		opts = append(opts, jwt.WithIssuer(issuer))
	}

	tokenExchangeVerifier, err := jwt.NewTokenVerifier(ctx, opts...)
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
	Caller             CallerIdentity
	Target             ClientID
	SubjectTokenClaims *jwt.AccessTokenClaims
	Roles              Roles
}

func (a *AuthorizationServer) AuthorizeRequest(ctx context.Context, request *TokenExchangeRequest) (*AuthorizationResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	caller, err := a.authenticateClient(ctx, request)
	if err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "verify_subject_token")
	subjectTokenClaims, err := a.verifySubjectToken(ctx, request.SubjectToken, caller.Client)
	finishStep(err)
	if err != nil {
		return nil, err
	}

	// Impersonation only starts a chain, so urn:nais:call_chain[0] is the impersonated client.
	if caller.Impersonator != nil && subjectTokenClaims.Issuer == string(a.Issuer) {
		return nil, errs.InvalidRequest(nil, "impersonation requires a subject token not issued by STS")
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "authorize_target")
	roles, err := a.ClientStore.AuthorizeTarget(ctx, caller.Client, request.Audience)
	finishStep(err)
	if errors.Is(err, ErrTargetUnauthorized) {
		return nil, errs.InvalidTarget(err, "client is not authorized for target %q", request.Audience)
	}
	if err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		Caller:             caller,
		Target:             request.Audience,
		SubjectTokenClaims: subjectTokenClaims,
		Roles:              roles,
	}, nil
}

func (a *AuthorizationServer) GrantHandler(ctx context.Context, request *TokenExchangeRequest) (*AccessTokenResponse, error) {
	finishGrant := a.Metrics.StartTokenGrant(ctx)
	var err error
	defer func() { finishGrant(err) }()

	result, err := a.AuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	response, err := a.CreateTokenResponse(ctx, result)
	if err != nil {
		return nil, err
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "token issued", a.logAttrs(result)...)
	return response, nil
}

func (a *AuthorizationServer) CreateTokenResponse(ctx context.Context, result *AuthorizationResult) (*AccessTokenResponse, error) {
	accessToken, err := a.CreateAccessToken(result)
	if err != nil {
		return nil, err
	}

	finishStep := a.Metrics.StartTokenStep(ctx, "get_signer")
	signer, err := a.KeyStore.Signer()
	finishStep(err)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}

	finishStep = a.Metrics.StartTokenStep(ctx, "sign_token")
	signed, err := accessToken.Sign(signer)
	finishStep(err)
	if err != nil {
		return nil, err
	}
	return &AccessTokenResponse{
		AccessToken:     signed,
		IssuedTokenType: oidc.AccessTokenType,
		TokenType:       oidc.BearerToken,
		ExpiresIn:       uint64(accessToken.ExpiresIn().Seconds()),
	}, nil
}

func (a *AuthorizationServer) logAttrs(result *AuthorizationResult) []slog.Attr {
	subjectIssuer := result.SubjectTokenClaims.Issuer
	attrs := []slog.Attr{
		slog.String("client_id", string(result.Caller.Client.ID)),
		slog.String("target", string(result.Target)),
		slog.Int("role_count", len(result.Roles)),
		slog.String("subject_token_issuer", subjectIssuer),
	}

	if alias, ok := a.GetIssuerAlias(jwt.Issuer(subjectIssuer)); ok {
		attrs = append(attrs, slog.String("idp_alias", alias))
	}

	return attrs
}

func (a *AuthorizationServer) verifySubjectToken(ctx context.Context, subjectToken string, client *Client) (*jwt.AccessTokenClaims, error) {
	claims, err := a.TokenExchangeVerifier.Verify(ctx, subjectToken, func(claims *jwt.AccessTokenClaims) error {
		// Only check these claims for subject tokens issued by this STS, since we don't control the claims of externally issued subject tokens.
		if claims.Issuer != string(a.Issuer) {
			return nil
		}

		if !slices.Contains(claims.Audience, string(client.ID)) {
			return fmt.Errorf("subject token audience %q does not contain client_id %q", claims.Audience, client.ID)
		}
		return nil
	})
	if err != nil {
		return nil, errs.InvalidRequest(err, "subject token is invalid")
	}

	return claims, nil
}
