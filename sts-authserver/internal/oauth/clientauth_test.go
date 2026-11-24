package oauth

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/require"
)

type impersonationClientStore struct {
	ClientStore
	client *Client
}

func (s impersonationClientStore) GetByID(id ClientID) (*Client, error) {
	if id != s.client.ID {
		return nil, ErrClientNotFound
	}
	return s.client, nil
}

func TestResolveCallerIdentityRejectsImpersonation(t *testing.T) {
	const issuer = "https://people.example"
	const clientID ClientID = "dev:team:app"
	for _, tt := range []struct {
		name            string
		requestedID     ClientID
		subject         string
		allowed         Impersonator
		untrustedIssuer bool
		wantErr         string
	}{
		{name: "missing client ID", wantErr: "client_id is required"},
		{name: "invalid client ID", requestedID: "invalid", wantErr: "invalid client_id"},
		{name: "unknown client ID", requestedID: "dev:team:unknown", wantErr: "client authentication failed"},
		{name: "wrong issuer", requestedID: clientID, subject: "alice", allowed: Impersonator{Issuer: "https://other.example", Subject: "alice"}, wantErr: "client authentication failed"},
		{name: "wrong subject", requestedID: clientID, subject: "bob", allowed: Impersonator{Issuer: issuer, Subject: "alice"}, wantErr: "client authentication failed"},
		{name: "empty subject", requestedID: clientID, allowed: Impersonator{Issuer: issuer}, wantErr: "failed to extract impersonator subject"},
		{name: "issuer not trusted by client environment", requestedID: clientID, subject: "alice", allowed: Impersonator{Issuer: issuer, Subject: "alice"}, untrustedIssuer: true, wantErr: "client authentication failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAuthorizationServerConfig()
			if tt.untrustedIssuer {
				cfg.Environments[0].ClientAuthIssuers = []string{"cluster-dev"}
			}
			server := &AuthorizationServer{
				ClientStore: impersonationClientStore{client: &Client{
					ID: clientID, Environment: "dev",
					AuthorizationPolicy: AuthorizationPolicy{AllowedImpersonators: []Impersonator{tt.allowed}},
				}},
				AuthorizationServerConfig: cfg,
			}
			claims := &jwt.AccessTokenClaims{Issuer: issuer, Subject: tt.subject, Claims: map[string]json.RawMessage{}}
			if tt.subject != "" {
				claims.Claims["sub"] = json.RawMessage(strconv.Quote(tt.subject))
			}
			_, err := server.resolveCallerIdentity(claims, tt.requestedID)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
