package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	// RegistrationClientOption configures a registration client.
	RegistrationClientOption func(client *RegistrationClient)
	// TokenCallback returns a bearer token for a registration request.
	TokenCallback func(ctx context.Context) (string, error)
)

// NewRegistrationClient creates a client for the STS issuer and generates a
// signing key for software statements. tokenCallback must be non-nil and is
// called for each request. The default HTTP client has a ten-second timeout.
func NewRegistrationClient(issuer STSIssuer, tokenCallback TokenCallback, opts ...RegistrationClientOption) (*RegistrationClient, error) {
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

// WithHTTPClient replaces the registration client's default HTTP client.
func WithHTTPClient(client *http.Client) RegistrationClientOption {
	return func(c *RegistrationClient) {
		c.httpClient = client
	}
}

// TokenFromFile returns a callback that reads a bearer token from path.
// It rereads the file on each request to support token rotation and trims
// surrounding whitespace. The callback does not use the context.
func TokenFromFile(path string) TokenCallback {
	return func(_ context.Context) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}

		accessToken := strings.TrimSpace(string(data))
		if accessToken == "" {
			return "", fmt.Errorf("token file %s is empty", path)
		}
		return accessToken, nil
	}
}

// Register signs statement with the client's key and submits it to STS to
// create or replace a registration. It requires HTTP 200 OK and returns the
// decoded registration response.
func (r *RegistrationClient) Register(ctx context.Context, statement SoftwareStatement) (*ClientRegistrationResponse, error) {
	ss, err := sign(statement, r.signer)
	if err != nil {
		return nil, fmt.Errorf("sign software statement: %w", err)
	}
	cr := ClientRegistration{ss}
	resp, err := r.sendRequest[ClientRegistrationResponse](ctx, http.MethodPost, "", cr, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp.Body, nil
}

// Delete removes the registration identified by clientID.
// It requires HTTP 204 No Content, including when the registration is missing.
func (r *RegistrationClient) Delete(ctx context.Context, clientID string) error {
	_, err := r.sendRequest[any](ctx, http.MethodDelete, clientID, nil, http.StatusNoContent)
	return err
}

// PublicKeySet returns the public key used to verify this client's software
// statements. The key remains unchanged for the lifetime of the client.
func (r *RegistrationClient) PublicKeySet() (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{r.publicKey},
	}, nil
}
