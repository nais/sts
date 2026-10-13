package sts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/oauth"
	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
)

type ClientID struct {
	Name      string
	Namespace string
	Cluster   string
}

func (a ClientID) String() string {
	return fmt.Sprintf("%s:%s:%s", a.Cluster, a.Namespace, a.Name)
}

type ClientRegistration struct {
	ClientName        string             `json:"client_name"`
	Jwks              jose.JSONWebKeySet `json:"jwks"`
	SoftwareStatement string             `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type SoftwareStatement struct {
	AppId                string   `json:"appId"`
	AccessPolicyInbound  []string `json:"accessPolicyInbound"`
	AccessPolicyOutbound []string `json:"accessPolicyOutbound"`
}

type Instance struct {
	BaseURL       string
	ClientID      string
	ClientJwk     *jose.JSONWebKey
	Metadata      *oauth.MetadataOAuth
	AuthTokenPath string // optional: path to service account token file
}

func NewInstance(baseURL, clientID string, clientJwk *jose.JSONWebKey, metadata *oauth.MetadataOAuth, authTokenPath string) Instance {
	return Instance{
		BaseURL:       baseURL,
		ClientID:      clientID,
		ClientJwk:     clientJwk,
		Metadata:      metadata,
		AuthTokenPath: authTokenPath,
	}
}

func (t *Instance) getAccessToken(endpoint string) (string, error) {
	if t.AuthTokenPath != "" {
		token, err := os.ReadFile(t.AuthTokenPath)
		if err != nil {
			return "", fmt.Errorf("unable to read token from %s: %w", t.AuthTokenPath, err)
		}
		accessToken := strings.TrimSpace(string(token))
		if accessToken == "" {
			return "", fmt.Errorf("token file %s is empty", t.AuthTokenPath)
		}
		return accessToken, nil
	}
	return ClientAssertion(t.ClientJwk, t.ClientID, endpoint)
}

func (t *Instance) RegisterClient(registration *ClientRegistration) error {
	endpoint := fmt.Sprintf("%s/registration/client", t.BaseURL)

	data, err := json.Marshal(registration)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	accessToken, err := t.getAccessToken(endpoint)
	if err != nil {
		return fmt.Errorf("unable to get token for invoking STS: %w", err)
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		response, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unable to register application with STS: %s: %s", resp.Status, response)
	}

	return nil
}

func (t *Instance) DeleteClient(ctx context.Context, appClientId ClientID) error {
	endpoint := fmt.Sprintf("%s/registration/client", t.BaseURL)

	request, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/%s", endpoint, url.QueryEscape(appClientId.String())), nil)
	if err != nil {
		return err
	}

	accessToken, err := t.getAccessToken(endpoint)
	if err != nil {
		return fmt.Errorf("unable to get token for invoking STS: %w", err)
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	msg, _ := io.ReadAll(resp.Body)

	return fmt.Errorf("delete client from STS: %s: %s", resp.Status, msg)
}

func MakeClientRegistration(operatorPrivateJwk *jose.JSONWebKey, appClientId ClientID, stsClient stsv1.STSClient) (*ClientRegistration, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: operatorPrivateJwk.Key}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", operatorPrivateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}
	builder := jwt.Signed(rsaSigner)

	softwareStatement, err := createSoftwareStatement(stsClient, appClientId)
	if err != nil {
		return nil, err
	}
	builder = builder.Claims(softwareStatement)

	rawJWT, err := builder.Serialize()
	if err != nil {
		return nil, err
	}

	return &ClientRegistration{
		ClientName:        appClientId.String(),
		SoftwareStatement: rawJWT,
	}, nil
}

// TODO: add ACL to spec
func createSoftwareStatement(stsClient stsv1.STSClient, appId ClientID) (*SoftwareStatement, error) {
	return &SoftwareStatement{
		AppId: appId.String(),
	}, nil
}

func ensureValidRule(rule *v1.AccessPolicyRule, appId ClientID) {
	if len(rule.Namespace) == 0 {
		rule.Namespace = appId.Namespace
	}
	if len(rule.Cluster) == 0 {
		rule.Cluster = appId.Cluster
	}
}
