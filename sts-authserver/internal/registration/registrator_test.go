package registration

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/nais/sts/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

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
		AuthorizationPolicy: []api.AuthorizationPolicy{
			{Consumer: api.Client{Namespace: "team-b", Name: "app-b"}, Roles: []string{"reader"}},
			{Consumer: api.Client{Namespace: "team-c", Name: "app-c"}},
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
