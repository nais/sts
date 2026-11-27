package registration

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/jwt"
	"github.com/nais/sts/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

func TestRegistratorUsesExplicitIssuerBinding(t *testing.T) {
	var server *httptest.Server
	var discoveryRequests atomic.Int32
	server = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		discoveryRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL + "/bound", "jwks_uri": server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	}))
	t.Cleanup(server.Close)

	cfg := oauth.DefaultAuthorizationServerConfig()
	cfg.Issuer = "https://sts.example"
	cfg.ClientAuthIssuers = oauth.ClientAuthIssuers{
		"bound": {
			Issuer: jwt.Issuer(server.URL + "/bound"), Alias: "kubernetes", Mode: oauth.ClientAuthWorkload,
			ClaimMappings:    oauth.ClaimMappings{Client: oauth.ClientClaims{Namespace: "namespace", Name: "name"}},
			ExpectedAudience: "nais", MaxTokenLifetime: time.Hour,
		},
		"unbound": {
			Issuer: jwt.Issuer(server.URL + "/unbound"), Alias: "other-cluster", Mode: oauth.ClientAuthWorkload,
			ClaimMappings:    oauth.ClaimMappings{Client: oauth.ClientClaims{Namespace: "namespace", Name: "name"}},
			ExpectedAudience: "nais", MaxTokenLifetime: time.Hour,
		},
		"employee": {
			Issuer: jwt.Issuer(server.URL + "/people"), Alias: "employee", Mode: oauth.ClientAuthImpersonation, ClaimMappings: oauth.ClaimMappings{Impersonator: &oauth.ImpersonatorClaims{Subject: "sub"}},
			ExpectedAudience: "nais", MaxTokenLifetime: time.Hour,
		},
	}
	cfg.Environments = oauth.Environments{{
		Name: "dev", ClientAuthIssuers: []string{"bound", "unbound", "employee"},
		Registrator: oauth.RegistratorConfig{
			IssuerRef: "bound", Subject: "operator", RegistratorJwksUri: server.URL + "/statement-jwks", SigningAlg: "ES256",
		},
	}}
	registrators, err := NewRegistrators(t.Context(), server.Client(), cfg)
	require.NoError(t, err)
	assert.EqualValues(t, 1, discoveryRequests.Load(), "only the bound registrator issuer should be discovered")
	registrator, err := registrators.getRegistrator(server.URL+"/bound", "operator")
	require.NoError(t, err)
	assert.Equal(t, oauth.Name("dev"), registrator.Environment)
	assert.Equal(t, server.URL+"/bound", registrator.AuthIssuer)
	for _, issuer := range []string{"/unbound", "/people"} {
		_, err := registrators.getRegistrator(server.URL+issuer, "operator")
		require.Error(t, err)
	}
}

func TestRegistratorVerifiesAPIClientStatement(t *testing.T) {
	captured := make(chan string, 1)
	mux := nethttp.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := api.NewRegistrationClient(api.STSIssuer(server.URL), func(context.Context) (string, error) {
		return "token", nil
	}, api.WithHTTPClient(server.Client()))
	require.NoError(t, err)
	keys, err := client.PublicKeySet()
	require.NoError(t, err)

	mux.HandleFunc("GET /jwks", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	})
	mux.HandleFunc("POST "+api.RegistrationPath, func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var request api.ClientRegistration
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			nethttp.Error(w, err.Error(), nethttp.StatusBadRequest)
			return
		}
		captured <- request.SoftwareStatement
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"env:team-a:app-a"}`))
	})
	statement := api.SoftwareStatement{
		Client: api.Client{Namespace: "team-a", Name: "app-a"},
		AuthorizationPolicy: api.AuthorizationPolicy{
			AllowedImpersonators: []api.ImpersonatorSubject{"alice"},
			Clients: []api.AuthorizedClient{
				{Namespace: "team-b", Name: "app-b", Roles: []string{"reader"}},
				{Namespace: "team-c", Name: "app-c"},
			},
		},
	}
	_, err = client.Register(t.Context(), statement)
	require.NoError(t, err)
	signed := <-captured
	registrator := Registrator{
		RequiredAlgs: []string{string(api.SoftwareStatementSigningAlgorithm)},
		KeySet:       rp.NewRemoteKeySet(server.Client(), server.URL+"/jwks"),
	}
	verified, err := registrator.VerifySoftwareStatement(t.Context(), signed)
	require.NoError(t, err)
	assert.Equal(t, statement, verified.SoftwareStatement)

	registrator.RequiredAlgs = []string{"RS256"}
	_, err = registrator.VerifySoftwareStatement(t.Context(), signed)
	assert.ErrorContains(t, err, "signature algorithm")
}
