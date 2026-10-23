package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type RegistrationClient struct {
	requester         requester
	signer            jose.Signer
	publicKey         jose.JSONWebKey
	authTokenCallback AuthTokenCallback
	STSIssuer
}

type (
	// RegistrationClientOption configures a registration client.
	RegistrationClientOption func(client *RegistrationClient)
	// AuthTokenCallback returns a bearer token for a registration request.
	AuthTokenCallback func(ctx context.Context) (string, error)
)

// NewRegistrationClient creates a client for the STS issuer and generates a
// signing key for software statements. authTokenCallback must be non-nil and is
// called for each request. The default HTTP client has a ten-second timeout.
func NewRegistrationClient(issuer STSIssuer, authTokenCallback AuthTokenCallback, opts ...RegistrationClientOption) (*RegistrationClient, error) {
	if err := issuer.validate(); err != nil {
		return nil, fmt.Errorf("validate issuer: %w", err)
	}
	r := requester{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}

	c := &RegistrationClient{
		STSIssuer:         issuer,
		requester:         r,
		authTokenCallback: authTokenCallback,
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
		c.requester = requester{httpClient: client}
	}
}

// TokenFromFile returns a callback that reads a bearer token from path.
// It rereads the file on each request to support token rotation and trims
// surrounding whitespace. The callback does not use the context.
func TokenFromFile(path string) AuthTokenCallback {
	return func(_ context.Context) (string, error) {
		// #nosec G304 -- The application supplies the token file path, not request input.
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
	return r.requester.Do[ClientRegistrationResponse](ctx, r.RegistrationEndpoint(), http.MethodPost, cr, http.StatusOK, r.authTokenCallback)
}

// Delete removes the registration identified by clientID.
// It requires HTTP 204 No Content, including when the registration is missing.
func (r *RegistrationClient) Delete(ctx context.Context, clientID string) error {
	_, err := r.requester.Do[any](ctx, r.DeleteEndpoint(clientID), http.MethodDelete, nil, http.StatusNoContent, r.authTokenCallback)
	return err
}

// PublicKeySet returns the public key used to verify this client's software
// statements. The key remains unchanged for the lifetime of the client.
func (r *RegistrationClient) PublicKeySet() (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{r.publicKey},
	}, nil
}

func (r *RegistrationClient) PublicKeySetHandler(w http.ResponseWriter, req *http.Request) {
	jwks, err := r.PublicKeySet()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get public key set: %v", err), http.StatusInternalServerError)
		return
	}

	contentType := "application/jwk-set+json"
	if req.Header.Get("Accept") == "application/json" {
		contentType = "application/json"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Add("Vary", "Accept")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode public key set: %v", err), http.StatusInternalServerError)
	}
}

// FetchSTSMetadata fetches the discovery metadata from the issuer's well-known endpoint.
// It requires HTTP 200 OK and returns the decoded metadata.
func (r *RegistrationClient) FetchSTSMetadata(ctx context.Context) (*DiscoveryMetadata, error) {
	metadata, err := r.requester.Do[DiscoveryMetadata](ctx, r.OAuthDiscoveryEndpoint(), http.MethodGet, nil, http.StatusOK, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery metadata: %w", err)
	}

	return metadata, nil
}
