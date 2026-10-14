package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	TokenCallback            func() (string, error)
)

func WithHTTPClient(client *http.Client) RegistrationClientOption {
	return func(c *RegistrationClient) {
		c.httpClient = client
	}
}

func NewRegistrationClient(issuer string, tokenCallback TokenCallback, opts ...RegistrationClientOption) (*RegistrationClient, error) {
	// TODO: validate issuer before setting baseURL
	c := &RegistrationClient{
		registerEndpoint: issuer + "/registration/register", // TODO: parse as url and append path with url.Path
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
	cr := ClientRegistration{
		ss,
	}

	data, err := json.Marshal(cr)
	if err != nil {
		return nil, fmt.Errorf("marshal client registration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.registerEndpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := r.tokenCallback()
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.doRequest[ClientRegistrationResponse](req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	return resp, nil
}

func (r *RegistrationClient) Delete(ctx context.Context, clientID string) error {
	// TODO
	return nil
}

func (r *RegistrationClient) PublicKeySet() (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{r.publicKey},
	}, nil
}

func (r *RegistrationClient) doRequest[T any](req *http.Request) (*T, error) {
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}
	response := new(T)
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(response); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return response, nil
}
