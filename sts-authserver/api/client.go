package api

import (
	"crypto"
	"net/http"
	"time"
)

type RegistrationClient struct {
	registerEndpoint string
	httpClient       *http.Client
}

type RegistrationClientOption func(client *RegistrationClient)

func WithHTTPClient(client *http.Client) RegistrationClientOption {
	return func(c *RegistrationClient) {
		c.httpClient = client
	}
}

func NewRegistrationClient(issuer string, privateKey crypto.PrivateKey, opts ...RegistrationClientOption) *RegistrationClient {
	// TODO: validate issuer before setting baseURL

	c := &RegistrationClient{
		registerEndpoint: issuer + "/registration/register", // TODO: parse as url and append path with url.Path
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (r *RegistrationClient) Register(statement SoftwareStatement) (*ClientRegistrationResponse, error) {
	// TODO
	return nil, nil
}

func (r *RegistrationClient) Delete(clientID string) error {
	// TODO
	return nil
}
