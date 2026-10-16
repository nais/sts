package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type RegistrationClient struct {
	registerEndpoint string
	httpClient       *http.Client
	signer           jose.Signer
	publicKey        jose.JSONWebKey
	tokenCallback    TokenCallback
}

type (
	RegistrationClientOption func(client *RegistrationClient)
	TokenCallback            func(ctx context.Context) (string, error)
)

func WithHTTPClient(client *http.Client) RegistrationClientOption {
	return func(c *RegistrationClient) {
		c.httpClient = client
	}
}

func TokenCallbackFromFile(path string) TokenCallback {
	return func(_ context.Context) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return string(bytes.TrimSpace(data)), nil
	}
}

func NewRegistrationClient(issuer STSIssuer, tokenCallback TokenCallback, opts ...RegistrationClientOption) (*RegistrationClient, error) {
	// TODO: validate issuer before setting baseURL
	c := &RegistrationClient{
		registerEndpoint: issuer.RegistrationEndpoint(),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout: 90 * time.Second,
			},
		},
		tokenCallback: tokenCallback,
	}

	for _, opt := range opts {
		opt(c)
	}

	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	signer, err := createSigner(key)
	if err != nil {
		return nil, err
	}
	c.signer = signer
	c.publicKey = key.Public()

	return c, nil
}

func (r *RegistrationClient) Register(ctx context.Context, statement SoftwareStatement) (*ClientRegistrationResponse, error) {
	ss, err := sign(statement, r.signer)
	if err != nil {
		return nil, fmt.Errorf("sign software statement: %w", err)
	}
	cr := ClientRegistration{ss}
	resp, err := r.sendRequest[ClientRegistrationResponse](ctx, http.MethodPost, "", cr)
	if err != nil {
		return nil, err
	}
	// TODO: validate response code?

	return &resp.Body, nil
}

func (r *RegistrationClient) Delete(ctx context.Context, clientID string) error {
	_, err := r.sendRequest[any](ctx, http.MethodDelete, clientID, nil)
	return err
}

func (r *RegistrationClient) PublicKeySet() (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{r.publicKey},
	}, nil
}
