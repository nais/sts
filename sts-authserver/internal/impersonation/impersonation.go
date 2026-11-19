package impersonation

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nais/sts/internal/jwt"
	stsmetrics "github.com/nais/sts/internal/metrics"
	"github.com/nais/sts/internal/oauth"
)

type Api struct {
	ClientAuthVerifier    *jwt.TokenVerifier
	ClientStore           oauth.ClientStore
	KeyStore              oauth.KeyStore
	TokenExchangeVerifier *jwt.TokenVerifier
	Metrics               *stsmetrics.Metrics
	oauth.AuthorizationServerConfig
	client *http.Client
}

func NewApi(ctx context.Context, client *http.Client, config oauth.AuthorizationServerConfig, store oauth.ClientStore, keyStore oauth.KeyStore, metrics *stsmetrics.Metrics) (*Api, error) {
	clientAuthVerifier, err := oauth.NewClientAuthTokenVerifier(ctx,
		client,
		config.Environments.ClientAuthIssuers(),
		config.ExpectedAudience,
		config.MaxClientAuthTokenLifetime,
	)
	if err != nil {
		return nil, fmt.Errorf("creating client auth verifier: %w", err)
	}

	opts := []jwt.TokenVerifierOption{
		jwt.WithHttpClient(client),
		jwt.WithIssuerAndKeySet(jwt.Issuer(config.Issuer), keyStore, string(oauth.InternalSigningAlgorithm)),
		jwt.WithIssuersFrom(clientAuthVerifier),
	}

	for _, issuer := range config.ExternalIssuers.Issuers() {
		opts = append(opts, jwt.WithIssuer(issuer))
	}

	tokenExchangeVerifier, err := jwt.NewTokenVerifier(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating token exchange verifier: %w", err)
	}

	return &Api{
		client:                    client,
		ClientAuthVerifier:        clientAuthVerifier,
		ClientStore:               store,
		KeyStore:                  keyStore,
		TokenExchangeVerifier:     tokenExchangeVerifier,
		Metrics:                   metrics,
		AuthorizationServerConfig: config,
	}, nil
}

func (i *Api) handle(ctx context.Context, user AuthenticatedUser, request Request) (any, error) {

	return nil, nil
}
